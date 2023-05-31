package com.security.study.model;

import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.sql.Timestamp;

@Entity
@Data // User를 form 데이터로 받아온 다음 해당 객체에서 바로 기입해야하기 때문에 Setter가 있는 @Data 사용
@NoArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id; // -> BIGINT
    private String username; // -> VARCHAR(255)
    private String password; // -> VARCHAR(255)
    private String email; // -> VARCHAR(255)

    // ROLE_USER, ROLE_ADMIN, ROLE_MANAGER
    private String role; // -> VARCHAR(255)

    private String provider;
    private String providerId;
    @CreationTimestamp
    private Timestamp createDate; // -> DATETIME(6)

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", email='" + email + '\'' +
                ", role='" + role + '\'' +
                ", createDate=" + createDate +
                '}';
    }

    @Builder
    public User(String username, String password, String email, String role, String provider, String providerId, Timestamp createDate) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.role = role;
        this.provider = provider;
        this.providerId = providerId;
        this.createDate = createDate;
    }
}
