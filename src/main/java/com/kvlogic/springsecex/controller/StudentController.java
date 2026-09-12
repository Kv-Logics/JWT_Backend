package com.kvlogic.springsecex.controller;

import com.kvlogic.springsecex.dto.ApiResponse;
import com.kvlogic.springsecex.model.Student;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

@RestController
public class StudentController {

    private final List<Student> students = new CopyOnWriteArrayList<>(
            List.of(
                    new Student(1, "Navin", 85),
                    new Student(2, "Kiran", 92),
                    new Student(3, "Alex", 78)
            ));

    @GetMapping("/students")
    public ResponseEntity<List<Student>> getStudents() {
        return ResponseEntity.ok(students);
    }

    @PostMapping("/students")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('SCOPE_students:write')")
    public ResponseEntity<ApiResponse<Student>> addStudent(@RequestBody Student student) {
        if (student == null || student.getName() == null || student.getName().trim().isEmpty()) {
            return ResponseEntity.badRequest().body(ApiResponse.error("Student name is required"));
        }
        // Auto-assign ID if missing or duplicate
        if (student.getId() <= 0 || students.stream().anyMatch(s -> s.getId() == student.getId())) {
            int nextId = students.stream().mapToInt(Student::getId).max().orElse(0) + 1;
            student.setId(nextId);
        }
        students.add(student);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.ok("Student added successfully", student));
    }

    @DeleteMapping("/students/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('SCOPE_students:delete')")
    public ResponseEntity<ApiResponse<String>> deleteStudent(@PathVariable int id) {
        boolean removed = students.removeIf(s -> s.getId() == id);
        if (removed) {
            return ResponseEntity.ok(ApiResponse.ok("Student with ID " + id + " deleted", null));
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error("Student with ID " + id + " not found"));
        }
    }
}
