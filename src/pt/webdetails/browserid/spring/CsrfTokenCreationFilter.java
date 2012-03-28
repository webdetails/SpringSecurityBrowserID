package pt.webdetails.browserid.spring;

import java.io.IOException;
import java.util.UUID;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.ui.SpringSecurityFilter;

/**
 * Filter that just adds a UUID to the session if not present.
 */
public class CsrfTokenCreationFilter extends SpringSecurityFilter {

  private String[] filterProcessesUrl;
  private String csrfTokenName = "suuid";
  private int order=0;
  
  public String[] getFilterProcessesUrl() {
    return filterProcessesUrl;
  }

  public void setFilterProcessesUrl(String[] filterProcessesUrl) {
    this.filterProcessesUrl = filterProcessesUrl;
  }

  @Override
  public int getOrder() {
    return order;
  }
  public void setOrder(int order){
    this.order = order;
  }
  
  /**
   * @return name of the session attribute to set
   */
  public String getCsrfTokenName() {
    return csrfTokenName;
  }

  /**
   * @param csrfTokenName name of the session attribute to set
   */
  public void setCsrfTokenName(String csrfTokenName) {
    this.csrfTokenName = csrfTokenName;
  }

  @Override
  protected void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
    Object uid = request.getSession().getAttribute(csrfTokenName);
    if(uid == null){
      uid =  UUID.randomUUID().toString();
      request.getSession().setAttribute(csrfTokenName, uid);
    }
    
    filterChain.doFilter(request, response);
  }

}
