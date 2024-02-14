package coml.ohgiraffers.security.user.service;

import coml.ohgiraffers.security.user.entity.User;
import coml.ohgiraffers.security.user.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public Optional<User> findByUserId(String id){
        Optional<User> user = userRepository.findByUserId(id);

        return user;
    }


}
