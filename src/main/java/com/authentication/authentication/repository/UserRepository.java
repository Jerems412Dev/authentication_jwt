    package com.authentication.authentication.repository;

    import com.authentication.authentication.entity.UserEntity;
    import org.springframework.data.jpa.repository.JpaRepository;

    import java.util.Optional;

    public interface UserRepository extends JpaRepository<UserEntity, Integer> {
        Optional<UserEntity> findByUsername(String username);
    }
