using System;

namespace AG.DTO
{
    public class AuthenticationResponse{
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public bool status { get; set; }
        public string Token { get; set; }
        public DateTime ExpireDate { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }


}
}
