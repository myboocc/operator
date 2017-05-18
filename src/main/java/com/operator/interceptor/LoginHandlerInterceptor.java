package com.operator.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import com.operator.bean.User;
import com.operator.util.Const;

/**
 * Created by xubinhui on 17-5-18.
 */
public class LoginHandlerInterceptor extends HandlerInterceptorAdapter {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // TODO Auto-generated method stub
        String path = request.getServletPath();
        if(path.matches(Const.NO_INTERCEPTOR_PATH)){
            return true;
        }else{
            //shiro管理的session
            Subject currentUser = SecurityUtils.getSubject();
            Session session = currentUser.getSession();
            User user = (User)session.getAttribute(Const.SESSION_USER);
            if(user!=null){
                return true;
            }else{
                //登陆过滤
                response.sendRedirect(request.getContextPath() + Const.LOGIN);
                return false;
            }
        }
    }

}
