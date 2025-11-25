package com.example.smartbus;

import java.time.LocalDate;

public class Student {
    public String usn;
    public String name;
    public String route;
    public LocalDate expires;
    public boolean active = true;

    public Student() {}

    public Student(String usn, String name, String route, LocalDate expires) {
        this.usn = usn;
        this.name = name;
        this.route = route;
        this.expires = expires;
        this.active = true;
    }
}
