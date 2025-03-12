using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using HotelManagementApi.DTOs;
using HotelManagementApi.Interfaces;
using HotelManagementApi.Models;

namespace HotelManagementApi.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        // Register a new user with a role
        public async Task<string> Register(RegisterDto registerDto)
        {
            var user = new ApplicationUser
            {
                UserName = registerDto.Email,
                Email = registerDto.Email,
                FullName = registerDto.FullName
            };
            var result = await _userManager.CreateAsync(user, registerDto.Password);

            if (!result.Succeeded) return null;

            // Ensure the role exists, then assign it
            if (!await _roleManager.RoleExistsAsync(registerDto.Role))
                await _roleManager.CreateAsync(new IdentityRole(registerDto.Role));

            await _userManager.AddToRoleAsync(user, registerDto.Role);
            return await GenerateJwtToken(user);
        }

        // Login and return JWT token
        public async Task<string> Login(LoginDto loginDto)
        {
            var user = await _userManager.FindByEmailAsync(loginDto.Email);
            if (user != null && await _userManager.CheckPasswordAsync(user, loginDto.Password))
            {
                return await GenerateJwtToken(user);
            }
            return null;
        }

        // Helper method to generate JWT token
        private async Task<string> GenerateJwtToken(ApplicationUser user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Email, user.Email)
            };

            var roles = await _userManager.GetRolesAsync(user);
            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}