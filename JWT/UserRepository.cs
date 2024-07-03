using System.Data.SqlClient;

namespace JWT
{
    public class UserRepository
    {
        private readonly string _connectionString;

        public UserRepository(IConfiguration configuration)
        {
            this._connectionString = configuration.GetConnectionString("CS");
        }

        public User GetUserByUsernameAndPassword(string username, string password)
        {
            using var connection = new SqlConnection(_connectionString);
            connection.Open();

            var query = "SELECT * FROM Users WHERE Username = @Username AND Password = @Password";
            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@Username", username);
            command.Parameters.AddWithValue("@Password", password);

            using var reader = command.ExecuteReader();
            if (reader.Read())
            {
                return new User
                {
                    Id = (int)reader["Id"],
                    Username = reader["Username"].ToString(),
                    Password = reader["Password"].ToString()
                };
            }

            return null;
        }
    }

}
