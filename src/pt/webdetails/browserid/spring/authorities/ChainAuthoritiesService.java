package pt.webdetails.browserid.spring.authorities;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

public class ChainAuthoritiesService implements InitializingBean, GrantedAuthoritiesService {
  
//  enum ChainMode {
//    FALLBACK,
//    UNION  
//  }
//  
//  private ChainMode chainMode = ChainMode.FALLBACK;
  
  private GrantedAuthoritiesService[] authoritiesServices;
  
  @Override
  public GrantedAuthority[] getAuthoritiesForUser(String email) throws UsernameNotFoundException {
    
    GrantedAuthority[] authorities = null;
    Exception lastException = null;
    for(GrantedAuthoritiesService service : authoritiesServices){
      try{
        authorities = service.getAuthoritiesForUser(email);
        if(authorities != null && authorities.length > 0){
          return authorities;
        }
      }
      catch(Exception e){
        lastException = e;
      }
    }
    throw new UsernameNotFoundException("Username not recognized by any service.", lastException);
  }
  
  public void setAuthoritiesServices(GrantedAuthoritiesService[] services){
    this.authoritiesServices = services;
  }

  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.notNull(authoritiesServices, "authoritiesServices must be set");
  }

}
