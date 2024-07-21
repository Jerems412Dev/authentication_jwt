package com.authentication.authentication.service;

import com.authentication.authentication.dto.UserDTO;
import com.authentication.authentication.entity.UserEntity;
import com.authentication.authentication.mapper.UserMapper;
import com.authentication.authentication.repository.UserRepository;
import com.authentication.authentication.security.UserPrincipal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService implements UserDetailsService {
    @Autowired
    private UserMapper userMapper;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private  PasswordEncoder passwordEncoder;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UserEntity> user = userRepository.findByUsername(username);
        return user.map(UserPrincipal::new)
                .orElseThrow(() -> new UsernameNotFoundException("UserName not found: " + username));
    }
    public String addUser(UserDTO register) {
        register.setPassword(passwordEncoder.encode(register.getPassword()));
        userMapper.toUserDTO(userRepository.save(userMapper.fromUserDTO(register)));
        return "user register successfully";
    }
}
