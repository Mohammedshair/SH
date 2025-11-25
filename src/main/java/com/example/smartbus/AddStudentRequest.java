package com.example.smartbus;

public class AddStudentRequest {
    public String usn;
    public String name;
    public String route;
    public String expires; // YYYY-MM-DD

    // default constructor required for JSON deserialization
    public AddStudentRequest() {}
}
