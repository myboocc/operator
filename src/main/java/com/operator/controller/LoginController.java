package com.operator.controller;

import com.operator.bean.User;
import com.operator.common.ServiceResponse;
import com.operator.service.IUserService;
import com.operator.util.Const;

import com.operator.util.Tools;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

import javax.annotation.Resource;

/**
 * Created by xubinhui on 17-5-18.
 */
@Controller
@RequestMapping("/login")
public class LoginController {

	@Resource
	private IUserService iUserService;

	@RequestMapping(value = "/toLogin", method = RequestMethod.GET)
	public String toLogin(Model model) {
		model.addAttribute("title", "运营商登陆");
		return "system/admin/login";
	}

	/**
	 * 请求登录，验证用户
	 */
	@RequestMapping(value = "/login", produces = "application/json;charset=UTF-8")
	@ResponseBody
	public ServiceResponse<User> login(Model model, String data) throws Exception {
		String keyData[] = data.replaceAll("qq583087977fh", "").replaceAll("QQ305858202fh", "").split(",fh,");
		if (null != keyData && keyData.length == 3) {
			// shiro管理的session
			Subject currentUser = SecurityUtils.getSubject();
			Session session = currentUser.getSession();
			// 获取session中的验证码
			String sessionCode = (String) session.getAttribute(Const.SESSION_SECURITY_CODE);
			String code = keyData[2];
			if (null == code || "".equals(code)) {
				// 验证码为空
				return ServiceResponse.createByErrorMessage("nullcode");
			}else{
				String username = keyData[0];
				String password = keyData[1];
				model.addAttribute("username", username);
				if(Tools.notEmpty(sessionCode) && sessionCode.equalsIgnoreCase(code)){
					String passwd = new SimpleHash("SHA-1", username, password).toString();	//密码加密
					model.addAttribute("password", passwd);
					ServiceResponse<User> user = iUserService.login(username, password);
					if(user != null){
						session.setAttribute(Const.SESSION_USER, user);
						session.removeAttribute(Const.SESSION_SECURITY_CODE);
						//shiro加入身份验证
						Subject subject = SecurityUtils.getSubject(); 
					    UsernamePasswordToken token = new UsernamePasswordToken(username, password); 
					    try { 
					        subject.login(token);
					    } catch (AuthenticationException e) { 
					    	return ServiceResponse.createByErrorMessage("userError");
					    }
					}else{
						//用户名或密码错误
						return ServiceResponse.createByErrorMessage("userError");
					}
				}else{
					//验证码有误
					return ServiceResponse.createByErrorMessage("codeError");
				}
				//验证成功
				return ServiceResponse.createBySuccess();
			}
		}else{
			//缺少参数
			return ServiceResponse.createByErrorMessage("missError");
		}
	}

}
