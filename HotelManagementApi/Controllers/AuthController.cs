using Microsoft.AspNetCore.Mvc;
using HotelManagementApi.DTOs;
using HotelManagementApi.Interfaces;

namespace HotelManagementApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        // POST: api/auth/register
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            var token = await _authService.Register(registerDto);
            if (token == null) return BadRequest("Registration failed");
            return Ok(new { Token = token });
        }

        // POST: api/auth/login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            var token = await _authService.Login(loginDto);
            if (token == null) return Unauthorized("Invalid credentials");
            return Ok(new { Token = token });
        }
    }
}