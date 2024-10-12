//using AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using WebApp.Identity.Models;

namespace WebApp.Identity.Controllers
{
    public class HomeController : Controller
    {
        private readonly UserManager<MyUser> _userManager;
        private readonly IUserClaimsPrincipalFactory<MyUser> _userClaimsPrincipalFactory;
        

        public HomeController(UserManager<MyUser> userManager, 
               IUserClaimsPrincipalFactory<MyUser> userClaimsPrincipalFactory)
        {
            _userManager = userManager;
            _userClaimsPrincipalFactory = userClaimsPrincipalFactory;
            
        }

        
        public IActionResult Privacy()
        {
            return View();
        }


        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(model.UserName);

                if (user != null && !await _userManager.IsLockedOutAsync(user))
                {
                    if (await _userManager.CheckPasswordAsync(user, model.Password))
                    {
                        if(!await _userManager.IsEmailConfirmedAsync(user))
                        {
                           ModelState.AddModelError("", "E-mail não está Válido!");
                           return View();    
                        }

                        await _userManager.ResetAccessFailedCountAsync(user);

                        if(await _userManager.GetTwoFactorEnableAsync(user))
                          {
                              var validator = await _userManager.GetValidTwoFactorProvidersAsync(user);

                              if(validator.Contains("Email"))
                              {
                                  var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                                  System.IO.File.WriteAllText("email2sv.txt", token);

                                      await HttpContext.SignInAsync(IdentityConstants.TwoFactorUserIdScheme,
                                           Store2FA(user.Id, "Email"));

                                      return RedirectToAction("TwoFactor");          
                              }
                          }

                        var principal = await _userClaimsPrincipalFactory.CreateAsync(user);                     

                        await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, principal);

                        return RedirectToAction("About");
                    }
                    
                    await _userManager.AccessFailedAsync(user);

                    if (await _userManager.IsLockedOutAsync(user))
                    {
                        //Email deve ser enviado com sugestão de mudança de senha!
                    }
                }
                ModelState.AddModelError("", "Usuário ou Senha invalida");
                return View();
            }
            return View();
        }

        public ClaimsPrincipal Store2FA (string userId, string provider)
        {
            var identity = new ClaimsIdentity(new List<Claim>
            {
                new Claim("sub", userId),
                new Claim("amr", provider)
            },  IdentityConstants.TwoFactorUserIdScheme);

            return new ClaimsPrincipal(identity);
        }

        [HttpGet]
        public async Task<IActionResult> Login()
        {
            return  View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(model.UserName);

                if (user == null)
                {
                    user = new MyUser
                    {
                        Id = Guid.NewGuid().ToString(),
                        UserName = model.UserName,
                        Email = model.UserName
                    };

                    var result = await _userManager.CreateAsync(user, model.Password);

                    if (result.Succeeded)
                    {
                        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        var confirmationEmail = Url.Action("ConfirmEmailAddress", "Home", 
                               new { token = token, email = user.Email }, Request.Scheme);

                        System.IO.File.WriteAllText("confirmationEmail.txt", confirmationEmail);

                       ViewData["SuccessMessage"] = "Verifique seu e-mail para confirmar o cadastro.";
                       return View(model);
                    }
                }
                else
                {
                ModelState.AddModelError("", "Usuário já existe!");
                }
            }
            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> ConfirmEmailAddress(string token, string email)
        {
            var user = await _userManager.FindByNameAsync(email);

            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);

                if (result.Succeeded)
                {
                   return View("Success");
                } 
            }

            return View("Error");
        }

        [HttpGet]
        public async Task<IActionResult> Register()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null)
                {
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var resetURL = Url.Action("ResetPassword", "Home", 
                        new { token = token, email = model.Email }, Request.Scheme);

                    System.IO.File.WriteAllText("resetLink.txt", resetURL);
                    string email = model.Email;
                    ViewData["SuccessMessage"] = $"Clique no Link enviado para o Email {email}";
                    return View(model);
                }
                ModelState.AddModelError("", "Invalid Request");
            }
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            return View(new ResetPasswordModel { Token = token, Email = email });
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null)
                {
                    var result = await _userManager.ResetPasswordAsync(user,
                        model.Token, model.Password);

                    if (!result.Succeeded)
                    {
                        foreach (var erro in result.Errors)
                        {
                            ModelState.AddModelError("", erro.Description);
                        }
                        return View();
                    }
                    ViewData["SuccessMessage"] = "Senha alterada com sucesso.";
                    return View(model);
                }
                ModelState.AddModelError("", "Invalid Request");
            }
            return View();
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> About()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Success()
        {
            return View();
        }

        [HttpGet]
        public IActionResult TwoFactory()
        {
            return  View();
        }
        
       [HttpPost]
       public async Task<IActionResult> TwoFactor(TwoFactorModel model)
       {
           var result = await HttpContext.AuthenticateAsync(IdentityConstants.TwoFactorUserIdScheme);
           if (!result.Succeeded)
           {
              ModelState.AddModelError("", "Seu token expirou!");
              return  View();
           }

           if (ModelState.IsValid)
           {
               var user = await _userManager.FindByIdAsync(result.Principal.FindfirstValue("sub"));
               if(user != null)
               {
                    var isvalid = await _userManager.VerifyTwoFactorTokenAsync(
                        user, 
                        result.Principal.FindfirstValue("amr"), model.Token);

                    if (isvalid)
                    {
                        await HttpContext.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme);

                        var ClaimsPrincipal = await _userClaimsPrincipalFactory.CreateAsync(user);
                        await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, claimsPrincipal);

                        return RedirectToAction("About");
                    }    
                   
                    ModelState.AddModelError("", "InvalidCastException Token");
                    return View();
               }
                ModelState.AddModelError("", "Invalid Request");
           }
             return View(); 
       }
    }
}
 