/*

package login.vecchio;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import login.model.Role;
import login.model.User;
import login.service.UserService;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;


public class CustomRefreshFilter {
    private static final transient byte[] keyHMAC =new byte[999999999];
    private static final SecureRandom secureRandom = new SecureRandom();
    public  void refreshFilter(String authorizationHeader, UserService userService, HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (authorizationHeader != null && authorizationHeader.startsWith("bearer")) {
            try {
                String userFingerprint = null;
                if (request.getCookies() != null && request.getCookies().length > 0) {
                    List<Cookie> cookies = Arrays.stream(request.getCookies()).collect(Collectors.toList());
                    Optional<Cookie> cookie = cookies.stream().filter(c -> "__Secure-Fgp"
                            .equals(c.getName())).findFirst();
                    if (cookie.isPresent()) {
                        userFingerprint = cookie.get().getValue();
                    }
                }
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] userFingerprintDigest = digest.digest(userFingerprint.getBytes("utf-8"));
                String userFingerprintHash = DatatypeConverter.printHexBinary(userFingerprintDigest);
                String refresh_token = authorizationHeader.substring("bearer".length());
                JWTVerifier verifier = JWT.require(Algorithm.HMAC256(keyHMAC))
                        .withClaim("userFingerprint", userFingerprintHash)
                        .build();
                DecodedJWT decodeJWT = verifier.verify(refresh_token);
                String username=decodeJWT.getSubject();
                User user= userService.getUser(username);
                RefreshNew(user,request,response,userService);
            } catch (Exception exception) {
                response.setHeader("error",exception.getMessage());
                response.setStatus(FORBIDDEN.value());
                // response.sendError(FORBIDDEN.value());
                Map<String,String> error=new HashMap<>();
                error.put("messaggio_errore",exception.getMessage());
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(),error);
            }
        }else{
            throw new RuntimeException("errore refresh Token");
        }
    }



    public  void RefreshNew(User user, HttpServletRequest request, HttpServletResponse response, UserService userService) throws IOException {
        byte[] randomFgp = new byte[50];
        secureRandom.nextBytes(randomFgp);
        String userFingerprint = DatatypeConverter.printHexBinary(randomFgp);
        String fingerprintCookie =  userFingerprint;

        Cookie cookie = new Cookie("__Secure-Fgp",fingerprintCookie);
        cookie.setPath("/api");
        response.addCookie(cookie);
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        byte[] userFingerprintDigest = digest.digest(userFingerprint.getBytes(StandardCharsets.UTF_8));
        String userFingerprintHash = DatatypeConverter.printHexBinary(userFingerprintDigest);

        Calendar c = Calendar.getInstance();
        Date now = c.getTime();
        c.add(Calendar.MINUTE, 10);
        Date expirationDate = c.getTime();
        Map<String, Object> headerClaims = new HashMap<>();
        headerClaims.put("typ", "JWT");
        String access_token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(expirationDate)
                .withIssuer(request.getRequestURL().toString())
                .withIssuedAt(now)
                .withNotBefore(now)
                .withClaim("userFingerprint", userFingerprintHash)
                .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                .withHeader(headerClaims)
                .sign(Algorithm.HMAC256(keyHMAC));


        String refresh_token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(expirationDate)
                .withIssuer(request.getRequestURL().toString())
                .withClaim("userFingerprint", userFingerprintHash)
                .sign(Algorithm.HMAC256(keyHMAC));

        //  response.setHeader("access_token",access_token);
        //  response.setHeader("refresh_token",refresh_token);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", access_token);
        tokens.put("refresh_token", refresh_token);
        response.setContentType(APPLICATION_JSON_VALUE);

        new ObjectMapper().writeValue(response.getOutputStream(), tokens);

    }
}


 */