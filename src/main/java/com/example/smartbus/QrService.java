package com.example.smartbus;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.*;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Service
public class QrService {

    private final Path qrsDir = Paths.get("src/main/resources/static/qr");

    public QrService() throws IOException {
        if (Files.notExists(qrsDir)) {
            Files.createDirectories(qrsDir);
        }
    }

    /**
     * Human-readable deterministic filename for USN: "USN.png"
     * Sanitizes a bit to avoid funky chars.
     */
    public String fileNameForUsn(String usn) {
        return usn.trim().replaceAll("[^A-Za-z0-9\\-_.]", "_") + ".png";
    }

    public Path getQrPathForUsn(String usn) {
        return qrsDir.resolve(fileNameForUsn(usn));
    }

    /**
     * Generate QR bytes for given content (typically the signed token),
     * save to disk if missing, and return PNG bytes.
     * If file exists, returns existing bytes and does NOT overwrite.
     */
    public byte[] generateAndSaveIfMissing(String content, String filename) throws Exception {

        Path out = qrsDir.resolve(filename);
        if (Files.exists(out)) {
            return Files.readAllBytes(out);
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        Map<EncodeHintType, Object> hints = new HashMap<>();
        hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");
        hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
        hints.put(EncodeHintType.MARGIN, 1);

        BitMatrix matrix = new com.google.zxing.MultiFormatWriter()
                .encode(content, BarcodeFormat.QR_CODE, 400, 400, hints);

        MatrixToImageWriter.writeToStream(matrix, "PNG", baos);
        byte[] png = baos.toByteArray();

        // atomic write
        Path tmp = qrsDir.resolve(filename + ".tmp-" + Instant.now().toEpochMilli());
        Files.write(tmp, png, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        Files.move(tmp, out, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);

        return png;
    }
}
