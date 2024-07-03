using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    
    public class AuthController : ControllerBase
    {
       
        private readonly JwtService _jwtService;
        private readonly UserRepository _userRepository;

        public AuthController(JwtService jwtService, UserRepository userRepository)
        {
            _jwtService = jwtService;
            _userRepository = userRepository;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            // Validate request
            if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
            {
                return BadRequest("Invalid login request");
            }

            // Authenticate user
            var user = _userRepository.GetUserByUsernameAndPassword(request.Username, request.Password);
            if (user == null)
            {
                return Unauthorized("Invalid username or password");
            }

            // Generate JWT token
            var token = _jwtService.GenerateToken(user);

            return Ok(new { Token = token });
        }


        [HttpGet]
        [Authorize]
        public IActionResult GetUserData()
        {
            // Access user claims
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var username = User.FindFirst(ClaimTypes.Name)?.Value;

            // Your logic to retrieve user data based on the claims
            var userData = new { UserId = userId, Username = username, AdditionalInfo = "Some additional data" };

            return Ok(userData);
        }
    }

    public class LoginRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}



