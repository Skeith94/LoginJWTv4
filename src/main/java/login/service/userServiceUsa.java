package login.service;

import login.model.Role;
import login.model.User;
import login.repo.RoleRepository;
import login.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional // serve per la gestione delle ACID connection con il db
@Slf4j
public class userServiceUsa implements UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user= userRepository.findByUsername(username);
        if(user==null){
            log.error("User non trovato nel  database");
            throw  new UsernameNotFoundException("User non trovato nel  database");
        }else{
            log.info("utente trovato nel db {}", username);
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role ->{
        authorities.add(new SimpleGrantedAuthority(role.getName()));
        } );
        return new org.springframework.security.core.userdetails.User(user.getUsername(),user.getPassword(),authorities);
    }

    public boolean checkUserByUsername(String username) throws UsernameNotFoundException {
        User user= userRepository.findByUsername(username);
        if(user==null){
            log.error("User non trovato nel  database");
            return false ;
        }else{
            log.info("utente trovato nel db {}",username);
            return  true;
        }
    }





    public User saveUser(User user) {
        log.info("salvo un nuovo utente {} nel db",user.getName());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }


    public Role saveRole(Role role) {
        log.info("salvo un nuovo ruolo {} nel db",role.getName());
        return roleRepository.save(role);
    }


    public void addRoleToUser(String username, String roleName) {
      log.info("aggiungo un ruolo {} all user {}",roleName, username);
      User user= userRepository.findByUsername(username);
      Role role= roleRepository.findByName(roleName);
      user.getRoles().add(role);
    }


    public User getUser(String username) {
        log.info("Fetching user {}",username);
        return userRepository.findByUsername(username);
    }


    public List<User> getUsers() {
        log.info("Fetching di tutti gli user {}");
        return userRepository.findAll();
    }

    public boolean checkUser(String username) throws UsernameNotFoundException {
        User User= userRepository.findByUsername(username);
        if(User ==null){
            log.error("User non trovato nel  database");
            return false ;
        }else{
            log.info("utente trovato nel db {}",username);
            return  true;
        }
    }

    public boolean checkEmail(String email) throws UsernameNotFoundException {
        User usercustom = userRepository.findByEmail(email);
        if(usercustom ==null){
            log.error("email non trovata");
            return false ;
        }else{
            log.info("email trovata nel db {}",email);
            return  true;
        }
    }


    public User getUserfromEmail(String email) throws UsernameNotFoundException {
        User usercustom = userRepository.findByEmail(email);
        if(usercustom ==null){
            log.error("email non trovata");
            return null;
        }else{
            log.info("email trovata nel db {}",email);
            return  usercustom;
        }
    }



    public void RemoveRole(String username, String roleName) {
        log.info("rimuovo un ruolo {} all user {}",roleName, username);
        User user= userRepository.findByUsername(username);
        Role role= roleRepository.findByName(roleName);
        user.getRoles().remove(role);
    }

}
