package com.operator.controller;

import com.operator.util.Const;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by xubinhui on 17-5-18.
 */
@Controller
@RequestMapping("/login")
public class LoginController {

    @RequestMapping(value = "/toLogin", method = RequestMethod.GET)
    public String toLogin(Model model){
        model.addAttribute("title","运营商登陆");
        return "system/admin/login";
    }

    /**
     * 请求登录，验证用户
     */
    @RequestMapping(value="/login" ,produces="application/json;charset=UTF-8")
    @ResponseBody
    public Object login()throws Exception{
        Map<String,String> map = new HashMap<String,String>();
        PageData pd = new PageData();
        pd = this.getPageData();
        String errInfo = "";
        String KEYDATA[] = pd.getString("KEYDATA").replaceAll("qq583087977fh", "").replaceAll("QQ305858202fh", "").split(",fh,");

        if(null != KEYDATA && KEYDATA.length == 3){
            //shiro管理的session
            Subject currentUser = SecurityUtils.getSubject();
            Session session = currentUser.getSession();
            String sessionCode = (String)session.getAttribute(Const.SESSION_SECURITY_CODE);		//获取session中的验证码

            String code = KEYDATA[2];
            if(null == code || "".equals(code)){
                errInfo = "nullcode"; //验证码为空
            }else{
                String USERNAME = KEYDATA[0];
                String PASSWORD  = KEYDATA[1];
                pd.put("USERNAME", USERNAME);
                if(Tools.notEmpty(sessionCode) && sessionCode.equalsIgnoreCase(code)){
                    String passwd = new SimpleHash("SHA-1", USERNAME, PASSWORD).toString();	//密码加密
                    pd.put("PASSWORD", passwd);
                    pd = userService.getUserByNameAndPwd(pd);
                    if(pd != null){
                        pd.put("LAST_LOGIN",DateUtil.getTime().toString());
                        userService.updateLastLogin(pd);
                        User user = new User();
                        user.setUSER_ID(pd.getString("USER_ID"));
                        user.setUSERNAME(pd.getString("USERNAME"));
                        user.setPASSWORD(pd.getString("PASSWORD"));
                        user.setNAME(pd.getString("NAME"));
                        user.setRIGHTS(pd.getString("RIGHTS"));
                        user.setROLE_ID(pd.getString("ROLE_ID"));
                        user.setLAST_LOGIN(pd.getString("LAST_LOGIN"));
                        user.setIP(pd.getString("IP"));
                        user.setSTATUS(pd.getString("STATUS"));
                        session.setAttribute(Const.SESSION_USER, user);
                        session.removeAttribute(Const.SESSION_SECURITY_CODE);

                        //shiro加入身份验证
                        Subject subject = SecurityUtils.getSubject();
                        UsernamePasswordToken token = new UsernamePasswordToken(USERNAME, PASSWORD);
                        try {
                            subject.login(token);
                        } catch (AuthenticationException e) {
                            errInfo = "身份验证失败！";
                        }

                    }else{
                        errInfo = "usererror"; 				//用户名或密码有误
                    }
                }else{
                    errInfo = "codeerror";				 	//验证码输入有误
                }
                if(Tools.isEmpty(errInfo)){
                    errInfo = "success";					//验证成功
                }
            }
        }else{
            errInfo = "error";	//缺少参数
        }
        map.put("result", errInfo);
        return AppUtil.returnObject(new PageData(), map);
    }

}
