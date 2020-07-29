package murraco.service;

import javax.servlet.http.HttpServletRequest;

import murraco.model.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import murraco.exception.CustomException;
import murraco.model.User;
import murraco.repository.UserRepository;
import murraco.security.JwtTokenProvider;

import java.util.List;

@Service
public class UserService {

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private PasswordEncoder passwordEncoder;

  @Autowired
  private JwtTokenProvider jwtTokenProvider;

  @Autowired
  private AuthenticationManager authenticationManager;

  public String signin(String username, String password) {
    try {
      authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
      StringBuilder sb = new StringBuilder();
      sb.append(jwtTokenProvider.createToken(username, userRepository.findByUsername(username).getRoles())+",");
      sb.append(jwtTokenProvider.createRefreshToken(username, userRepository.findByUsername(username).getRoles()));
      return sb.toString();
    } catch (AuthenticationException e) {
      throw new CustomException("Invalid username/password supplied", HttpStatus.UNPROCESSABLE_ENTITY);
    }
  }

  public String signup(User user) {
    if (!userRepository.existsByUsername(user.getUsername())) {
      user.setPassword(passwordEncoder.encode(user.getPassword()));
      userRepository.save(user);
      StringBuilder sb = new StringBuilder();
      sb.append(jwtTokenProvider.createToken(user.getUsername(), user.getRoles())+",");
      sb.append(jwtTokenProvider.createRefreshToken(user.getUsername(), user.getRoles()));
      return sb.toString();
    } else {
      throw new CustomException("Username is already in use", HttpStatus.UNPROCESSABLE_ENTITY);
    }
  }

  public void delete(String username) {
    userRepository.deleteByUsername(username);
  }

  public User search(String username) {
    User user = userRepository.findByUsername(username);
    if (user == null) {
      throw new CustomException("The user doesn't exist", HttpStatus.NOT_FOUND);
    }
    return user;
  }

  public User whoami(HttpServletRequest req) {
    return userRepository.findByUsername(jwtTokenProvider.getUsername(jwtTokenProvider.resolveToken(req)));
  }

  public String refresh(String refreshToken) {
      try {
          jwtTokenProvider.validateToken(refreshToken);
          String username = jwtTokenProvider.getUsername(refreshToken);
          List<Role> roles = userRepository.findByUsername(username).getRoles();
          return jwtTokenProvider.createToken(username, roles);
      } catch (AuthenticationException e) {
          throw new CustomException("Invalid Refresh Token", HttpStatus.UNPROCESSABLE_ENTITY);
      }
  }

}
