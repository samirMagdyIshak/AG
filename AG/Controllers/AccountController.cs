using AG.DTO;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualBasic;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using AG.Migrations;
using Microsoft.AspNetCore.Authorization;

namespace AG.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private UserManager<IdentityUser> userManager;
        private RoleManager<IdentityRole> roleManager;

        public SignInManager<IdentityUser> SignInManager { get; }

        private IConfiguration configuration;
        private AppContext appContext;


        public AccountController(UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            IConfiguration configuration,AppContext appContext,
            RoleManager<IdentityRole> roleManager
            )
        {
            this.userManager = userManager;
            this.SignInManager = signInManager;
            this.configuration = configuration;
            this.appContext = appContext;
            this.roleManager = roleManager;
        }


        [HttpPost("Create")]
        public async Task<IActionResult> create(UserSignUp userCredentials)
        {
            var user=new IdentityUser { Email=userCredentials.Email,UserName=userCredentials.UserName};
            var result = await userManager.CreateAsync(user,userCredentials.Password);
            if (result.Succeeded)
            {
                return Ok(await BuildToken(new UserSigninDTO { Email=userCredentials.Email,Password=userCredentials.Password}));
            }
            else return BadRequest(result.Errors);
           

        }

        [HttpPost("login")]
        public async Task<ActionResult<AuthenticationResponse>> login(UserSigninDTO userSignin)
        {
            var user = await userManager.FindByEmailAsync(userSignin.Email);
            var result = await SignInManager.PasswordSignInAsync(user, userSignin.Password, userSignin.RememberMe, false);
            if (result.Succeeded)
                return  Ok(await BuildToken(userSignin));
            return BadRequest("Incorrect login");
        }


        private async Task<AuthenticationResponse> BuildToken(UserSigninDTO userCredentials)
        {
            var claims1 = new List<Claim>()
            {
                new Claim("email", userCredentials.Email)
            };

            var user = await userManager.FindByEmailAsync(userCredentials.Email);
            var claimsDB = await userManager.GetClaimsAsync(user);
            var roles=await userManager.GetRolesAsync(user);

            claims1.AddRange(claimsDB);
            foreach(var role in roles)
            {
                claims1.Add(new Claim(ClaimTypes.Role, role));  
            }
            

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["keyjwt"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var expiration = DateTime.UtcNow.AddYears(1);

            var token = new JwtSecurityToken(issuer: null, audience: null, claims: claims1,
                expires: expiration, signingCredentials: creds);

            return new AuthenticationResponse()
            {
                Username = user.UserName,
                status = true,
                Email=userCredentials.Email,
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                ExpireDate = expiration
            };
        }

        [HttpPost("roles")]
       
        public async Task<IActionResult> roles()
        {
            
            //await roleManager.CreateAsync(new IdentityRole("AI"));
            //await roleManager.CreateAsync(new IdentityRole("Embedded"));

            return Ok();
        }

    }
}
