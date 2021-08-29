package com.example.demo.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

//klasa z listą studentów
@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    //tworzenie listy studentów i dodanie do niej trzech przykładów

    private static final List<Student> STUDENT = Arrays.asList(
            new Student(1, "Pola Lola"),
            new Student(2, "Kaja Baja"),
            new Student(3, "Malwina Inna")
    );

    //mapowanie po ścieżce api i użycie streama do znalezienia konkretnego studenta po ID(studentId)
    @GetMapping(path = "{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId) {
        return STUDENT.stream()
                .filter(student -> studentId.equals(student.getStudentId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Student " + studentId + " does not exists"));
    }
}
