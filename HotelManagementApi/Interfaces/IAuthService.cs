using HotelManagementApi.DTOs;

namespace HotelManagementApi.Interfaces
{
    public interface IAuthService
    {
        Task<string> Register(RegisterDto registerDto);
        Task<string> Login(LoginDto loginDto);
    }
}