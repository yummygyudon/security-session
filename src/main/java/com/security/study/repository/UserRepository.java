package com.security.study.repository;

import com.security.study.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

// CRUD 함수는 자체적으로 JpaRepository 에 내포
// @Repository 도 JpaRepository가 가지고 있어서 자동으로 IoC
public interface UserRepository extends JpaRepository<User, Integer> {
    // READ
    User findByUsername(String name);
}
