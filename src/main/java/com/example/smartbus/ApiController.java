package com.example.smartbus;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.Base64;

@RestController
@RequestMapping("/api")
public class ApiController {

    // In-memory student store (existing behavior)
    private final Map<String, Student> students = new ConcurrentHashMap<>();

    // QR helper service (writes files, generates png bytes)
    private final QrService qrService;

    // where QR files live (static resources)
    private final Path qrsDir = Paths.get("src/main/resources/static/qr");

    // per-USN locks to prevent duplicate generation under concurrency
    private final ConcurrentHashMap<String, Object> locks = new ConcurrentHashMap<>();

    // HMAC secret
    private static final byte[] SECRET = Optional.ofNullable(System.getenv("APP_SECRET"))
            .map(String::getBytes)
            .orElse("ReplaceThisWithAStrongSecretKey123!".getBytes(StandardCharsets.UTF_8));
    private static final String HMAC_ALGO = "HmacSHA256";

    @Autowired
    public ApiController(QrService qrService) {
        this.qrService = qrService;
        try {
            if (Files.notExists(qrsDir)) Files.createDirectories(qrsDir);
        } catch (IOException ignored) {}
    }

    // =============================
    // ADD STUDENT
    // =============================
    @PostMapping("/add-student")
    public ResponseEntity<?> addStudent(@RequestBody AddStudentRequest req) throws Exception {
        if (req.usn == null || req.usn.isBlank())
            return ResponseEntity.badRequest().body(Map.of("error", "usn-required"));

        LocalDate expires;
        try {
            expires = LocalDate.parse(req.expires);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid-date"));
        }

        Student s = new Student(
                req.usn.trim(),
                req.name == null ? "" : req.name.trim(),
                req.route == null ? "" : req.route.trim(),
                expires
        );

        students.put(s.usn, s);

        String issued = LocalDate.now().toString();
        String payload = String.join("|", s.usn, s.name, s.route, s.expires.toString(), issued);
        String token = makeToken(payload);

        return ResponseEntity.ok(Map.of(
                "token", token,
                "payload", payload
        ));
    }

    // =============================
    // VERIFY TOKEN
    // =============================
    @PostMapping("/verify")
    public ResponseEntity<ScanResponse> verify(@RequestBody ScanRequest req) throws Exception {
        ScanResponse resp = new ScanResponse();

        String token = req.token;
        String payload;

        try {
            payload = decodeAndVerify(token);
        } catch (TokenException te) {
            resp.result = "NO_ENTRY";
            resp.reason = te.getMessage();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(resp);
        }

        String[] parts = payload.split("\\|", -1);
        if (parts.length < 5) {
            resp.result = "NO_ENTRY";
            resp.reason = "invalid-payload-format";
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(resp);
        }

        String usn = parts[0];
        String routeInToken = parts[2];
        String expiresStr = parts[3];

        Student s = students.get(usn);
        if (s == null) {
            resp.result = "NO_ENTRY";
            resp.reason = "usn-not-found";
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(resp);
        }

        resp.usn = usn;
        resp.name = s.name;

        LocalDate expires;

        try {
            expires = LocalDate.parse(expiresStr);
        } catch (DateTimeParseException e) {
            resp.result = "DENY";
            resp.reason = "invalid-expiry-in-token";
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(resp);
        }

        if (expires.isBefore(LocalDate.now())) {
            resp.result = "DENY";
            resp.reason = "expired";
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(resp);
        }

        if (!routeInToken.equalsIgnoreCase(s.route)) {
            resp.result = "DENY";
            resp.reason = "route-mismatch";
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(resp);
        }

        resp.result = "ALLOW";
        resp.reason = "ok";
        return ResponseEntity.ok(resp);
    }

    // =============================
    // GET QR IMAGE: /api/qr/{usn}
    // if file exists return it, otherwise sign payload -> token, generate QR (token encoded), save and return
    // =============================
    @GetMapping(value = "/qr/{usn}", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> getQrForUsn(@PathVariable String usn) throws Exception {
        Student s = students.get(usn);
        if (s == null) return ResponseEntity.notFound().build();

        // PAYLOAD
        String payload = String.join("|",
                s.usn, s.name, s.route, s.expires.toString(),
                LocalDate.now().toString());

        // SIGN TOKEN (this is what must be inside QR)
        String token = makeToken(payload);

        String filename = qrService.fileNameForUsn(s.usn);
        Path file = qrService.getQrPathForUsn(s.usn);

        if (Files.exists(file)) {
            byte[] bytes = Files.readAllBytes(file);
            return ResponseEntity.ok().contentType(MediaType.IMAGE_PNG).body(bytes);
        } else {
            Object lock = locks.computeIfAbsent(s.usn, k -> new Object());
            synchronized (lock) {
                try {
                    if (Files.exists(file)) {
                        byte[] bytes = Files.readAllBytes(file);
                        return ResponseEntity.ok().contentType(MediaType.IMAGE_PNG).body(bytes);
                    }
                    // IMPORTANT: pass the signed token to generator
                    byte[] png = qrService.generateAndSaveIfMissing(token, filename);
                    return ResponseEntity.ok().contentType(MediaType.IMAGE_PNG).body(png);
                } finally {
                    locks.remove(s.usn, lock);
                }
            }
        }
    }

    // =============================
    // POST /api/generate-qr?usn=...
    // create (if missing) a QR for student USN containing the SIGNED token; return { "url": "/qr/USN.png" }
    // =============================
    @PostMapping("/generate-qr")
    public ResponseEntity<Map<String, String>> generateQr(@RequestParam String usn) {
        try {
            if (usn == null || usn.isBlank()) {
                return ResponseEntity.badRequest().body(Map.of("error", "usn-required"));
            }

            usn = usn.trim();
            Student s = students.get(usn);
            if (s == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("error", "usn-not-found"));
            }

            String payload = String.join("|",
                    s.usn, s.name, s.route, s.expires.toString(),
                    LocalDate.now().toString());

            // SIGNED token
            String token = makeToken(payload);

            String filename = qrService.fileNameForUsn(s.usn);
            Path out = qrService.getQrPathForUsn(s.usn);

            if (Files.exists(out)) {
                return ResponseEntity.ok(Map.of("url", "/qr/" + filename));
            }

            Object lock = locks.computeIfAbsent(s.usn, k -> new Object());
            synchronized (lock) {
                try {
                    if (!Files.exists(out)) {
                        qrService.generateAndSaveIfMissing(token, filename);
                    }
                    return ResponseEntity.ok(Map.of("url", "/qr/" + filename));
                } finally {
                    locks.remove(s.usn, lock);
                }
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    // =============================
    // GET /api/qr-list
    // =============================
    @GetMapping("/qr-list")
    public ResponseEntity<List<String>> listQrs() {
        try {
            if (Files.notExists(qrsDir)) return ResponseEntity.ok(Collections.emptyList());
            List<String> urls = Files.list(qrsDir)
                    .filter(Files::isRegularFile)
                    .map(p -> "/qr/" + p.getFileName().toString())
                    .collect(Collectors.toList());
            return ResponseEntity.ok(urls);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(List.of());
        }
    }

    // =============================
    // Token generation (HMAC + base64url)
    // =============================
    private String makeToken(String payload) throws Exception {
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();

        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        String payloadB64 = enc.encodeToString(payloadBytes);

        byte[] sig = hmac(payloadBytes);
        String sigB64 = enc.encodeToString(sig);

        return payloadB64 + "." + sigB64;
    }

    // =============================
    // Token verification
    // =============================
    private String decodeAndVerify(String token) throws Exception {
        if (!token.contains("."))
            throw new TokenException("invalid-token-format");

        String[] parts = token.split("\\.", 2);
        Base64.Decoder dec = Base64.getUrlDecoder();

        byte[] payloadBytes = dec.decode(parts[0]);
        byte[] sigBytes = dec.decode(parts[1]);

        byte[] expectedSig = hmac(payloadBytes);

        if (!MessageDigest.isEqual(expectedSig, sigBytes))
            throw new TokenException("invalid-signature");

        return new String(payloadBytes, StandardCharsets.UTF_8);
    }

    // HMAC signing
    private byte[] hmac(byte[] data) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGO);
        mac.init(new SecretKeySpec(SECRET, HMAC_ALGO));
        return mac.doFinal(data);
    }

    // Token exception
    static class TokenException extends Exception {
        TokenException(String msg) { super(msg); }
    }
}
