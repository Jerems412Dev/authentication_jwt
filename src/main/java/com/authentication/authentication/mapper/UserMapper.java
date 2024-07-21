package com.authentication.authentication.mapper;

import com.authentication.authentication.dto.UserDTO;
import com.authentication.authentication.entity.UserEntity;
import org.mapstruct.Mapper;

import java.util.List;

@Mapper
public interface UserMapper {
    UserDTO toUserDTO(UserEntity userEntity);
    UserEntity fromUserDTO(UserDTO userDTO);
}
