    package com.authentication.authentication.entity;

    import jakarta.persistence.*;
    import lombok.Data;
    import lombok.NoArgsConstructor;

    import java.util.Date;

    @Entity
    @Data
    @NoArgsConstructor
    @Table(name = "apitokens")
    public class ApiToken {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private long id;
        private String username;
        @Column(name = "created_at", nullable = false, updatable = false)
        private Date createdAt;
        @Column(name = "updated_at", nullable = false)
        private Date updatedAt;
        private Boolean isValid;
        private String token;
    }
