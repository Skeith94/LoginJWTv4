//login api JWT #SecurityFilterChain implement #token cryptography #hardened cookie no Token Sidejacking XSS



package login;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import login.model.Role;
import login.model.User;
import login.security.TokenCipher;
import login.service.userServiceUsa;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;


//login api JWT #SecurityFilterChain implement #token cryptography #hardened cookie no Token Sidejacking XSS
@SpringBootApplication
public class loginapplication {



    private static final SecureRandom secureRandom = new SecureRandom();

    public static TokenCipher tokenCipher;
    public static KeysetHandle keyCiphering;


    public static final transient byte[] keyHMAC =new byte[500];

    public static void main(String[] args) {

        secureRandom.nextBytes(keyHMAC);

        try {
            tokenCipher = new TokenCipher();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        try {
            keyCiphering = KeysetHandle.generateNew(AeadKeyTemplates.AES128_GCM);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
           
        SpringApplication.run(loginapplication.class, args);

    }

    @Bean
    CommandLineRunner run(userServiceUsa userService) {
        return args -> {
            userService.saveRole(new Role(null, "ROLE_GUEST"));
            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_MANAGER"));
            userService.saveRole(new Role(null, "ROLE_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            userService.saveUser(new User(null, "vito malato", "vito", "1234", new ArrayList<>(),"vito@gmail.com"));
            userService.saveUser(new User(null, "danilo bella", "danilo", "1234", new ArrayList<>(),"danilo@gmail.com"));
            userService.saveUser(new User(null, "ricardo milos", "milos", "1234", new ArrayList<>(),"milos@gmail.com"));
            userService.saveUser(new User(null, "zio peppe", "peppe", "1234", new ArrayList<>(),"peppe@gmail.com"));

            userService.addRoleToUser("vito", "ROLE_SUPER_ADMIN");
            userService.addRoleToUser("danilo", "ROLE_ADMIN");
            userService.addRoleToUser("milos", "ROLE_MANAGER");
            userService.addRoleToUser("peppe", "ROLE_USER");
        };
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}








