package pt.webdetails.browserid.spring.authorities;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.DataAccessException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.userdetails.User;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;


/**
 * UserDetailsService wrapping a GrantedAuthoritiesService
 * All attributes beyond {@link UserDetails#getUsername()} and {@link UserDetails#getAuthorities())} are meaningless in this implementation  
 */

public class GrantedAuthoritiesUserDetailsService implements InitializingBean, UserDetailsService {

  private GrantedAuthoritiesService authoritiesService;
  private static final String PASSWORD = "";
  
  @Override
  public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException, DataAccessException {
    
    GrantedAuthority[] authorities = authoritiesService.getAuthoritiesForUser(userName);
    
    if(authorities == null || authorities.length == 0) throw new UsernameNotFoundException("No authorities can be mapped to user");
      
    return new User(userName, PASSWORD, true, true, true, true, authorities);
    
  }
  
  public void setAuthoritiesService(GrantedAuthoritiesService authoritiesService){
    this.authoritiesService = authoritiesService;
  }

  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.notNull(authoritiesService, "authoritiesService must be set");
  }

}
