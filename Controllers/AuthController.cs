using AngularAuthWebAPI.Context;
using AngularAuthWebAPI.Models.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Text;
using Microsoft.EntityFrameworkCore;
using AngularAuthWebAPI.Helpers;
using System.Security.Cryptography;
using System;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace AngularAuthWebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _authContext;
        public AuthController(AppDbContext appDbContext)
        {
            _authContext = appDbContext;
        }

        [HttpPost]
        public bool Signup(AuthUser user)
        {
            bool isSignedUp = false;
            return isSignedUp;
        }


        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] AuthUser userObj)
        {
            if (userObj == null)
                return BadRequest();

            var users = await _authContext.AuthUsers.FirstOrDefaultAsync(x => x.Email == userObj.Email);
            if (users == null)
            {
                return NotFound(new { Message = "User Not Found" });
            }
            
            //    if (!PasswordHasher.VerifyPassword(userObj.Password, users.Password))
            //    {
            //        return BadRequest(new { Message = "Password is incorrect!" });
            //    }
            //    return Ok(new { token = users.Token, Message = "Login Success" });
            
            if (!PasswordHasher.VerifyPassword(userObj.Password, users.Password))
            {
                return BadRequest(new { Message = "Password is incorrect!" });
            }

            users.Token = CreateToken(users);
            var newAccessToken = users.Token;
            var newRefreshToken = CreateRefreshToken();
            users.RefreshTokenExpiryTime = DateTime.Now.AddDays(5);
            users.RefreshToken = newRefreshToken;
            return Ok(new TokenApiDto()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }

        [HttpPost("register")]
        public async Task<IActionResult> registerUser([FromBody] AuthUser userObj)
        {
            if (userObj == null)
            {
                return BadRequest();
            }

            if (await CheckEmailExistAsync(userObj.Email))
            {
                return BadRequest(new { Message = "Email Already Exist!" });
            }

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = CreateToken(userObj);
            await _authContext.AuthUsers.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new { Message = "User Added" });
        }


        //private async Task<bool> CheckEmailExistAsync(string email)
        //{
        //    return await _authContext.AuthUsers.AnyAsync(x => x.Email == email);
        //}
        private Task<bool> CheckEmailExistAsync(string email)
            => _authContext.AuthUsers.AnyAsync(x => x.Email == email);

        private string CheckPasswordStrength(string password)
        {
            StringBuilder strB = new StringBuilder();
            if (password.Length < 8)
            {
                strB.Append("Minimum password length should be 8" + Environment.NewLine);
            }
            if (Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]") &&
            Regex.IsMatch(password, "[0-9]"))
            {
                strB.Append("Password Should be Alphanumeric" + Environment.NewLine);
            }
            if (Regex.IsMatch(password, "[@,<,>!@#$%^&*()?></.,|}{]"))
            {
                strB.Append("Password Should contain special character" + Environment.NewLine);
            }
            return strB.ToString();

        }

        private string CreateToken(AuthUser userObj)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("superSecretKey@345");
            var identity = new ClaimsIdentity(new Claim[] {
                new Claim(ClaimTypes.Role, userObj.Role),
                new Claim(ClaimTypes.Name, $"{userObj.Email}")
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddSeconds(10),
                SigningCredentials = credentials
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);
        }

        [HttpGet("GetAllUsers")]
        public async Task<IActionResult> GetAllUsers()
        {
            return Ok(await this._authContext.AuthUsers.ToListAsync());

        }

        private string CreateRefreshToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert.ToBase64String(tokenBytes);
            var tokenInUser = _authContext.AuthUsers.Any(a => a.RefreshToken == refreshToken);
            if (tokenInUser)
            {
                return CreateRefreshToken();
            }
            else
            {
                return refreshToken;
            }
        }

        private ClaimsPrincipal GetPrincipleFromExpiredToken(string token)
        {
            var key = Encoding.ASCII.GetBytes("superSecretKey@345");
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken secuirtyToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out secuirtyToken);
            var jwtSecurityToken = secuirtyToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("This is invalid token");
            }
            else
            {
                return principal;
            }
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(TokenApiDto tokenApiDto)
        {
            if (tokenApiDto is null)
            {
                return BadRequest("Invalid Client Request");
            }
            string accessToken = tokenApiDto.AccessToken;
            string refreshToken = tokenApiDto.RefreshToken;
            var principal = GetPrincipleFromExpiredToken(accessToken);
            var username = principal.Identity.Name;
            var user = await _authContext.AuthUsers.FirstOrDefaultAsync(x => x.Email == username);
            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return BadRequest("Invalid Request");
            }
            var newAccessToken = CreateToken(user);
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            await _authContext.SaveChangesAsync();
            return Ok(new TokenApiDto()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });


        }
    }
}
