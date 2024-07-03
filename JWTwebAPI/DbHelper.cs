using System.Data;
using System.Data.SqlClient;
using System.Data.SqlTypes;

namespace JWTwebAPI
{
    public  class DbHelper
    {
        private const string ConnectionString = "Server=DESKTOP-425VFSO\\SQLEXPRESS;Database=MyDB;Trusted_Connection=True;TrustServerCertificate=True;";

        public static async Task<User> GetUserAsync(string username)
        {
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                await connection.OpenAsync();

                using (SqlCommand command = new SqlCommand("GetUserByUsername", connection))
                {
                    command.CommandType = CommandType.StoredProcedure;
                    command.Parameters.AddWithValue("@Username", username);

                    using (SqlDataReader reader = await command.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync())
                        {
                            return new User
                            {
                                UserName = reader["UserName"].ToString(),
                                PasswordHash = (byte[])reader["PasswordHash"],
                                PasswordSalt = (byte[])reader["PasswordSalt"],
                                RefreshToken = reader["RefreshToken"].ToString(),
                                TokenCreated = (DateTime)reader["TokenCreated"],
                                TokenExpires = (DateTime)reader["TokenExpires"]
                            };
                        }
                        return null;
                    }
                }
            }
        }

        public static async Task InsertUserAsync(User user)
        {
            user.TokenCreated = user.TokenCreated < SqlDateTime.MinValue.Value
    ? SqlDateTime.MinValue.Value
    : (user.TokenCreated > SqlDateTime.MaxValue.Value ? SqlDateTime.MaxValue.Value : user.TokenCreated);

            user.TokenExpires = user.TokenExpires < SqlDateTime.MinValue.Value
                ? SqlDateTime.MinValue.Value
                : (user.TokenExpires > SqlDateTime.MaxValue.Value ? SqlDateTime.MaxValue.Value : user.TokenExpires);

            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                await connection.OpenAsync();

                using (SqlCommand command = new SqlCommand("InsertUser", connection))
                {
                    command.CommandType = CommandType.StoredProcedure;
                    command.Parameters.AddWithValue("@Username", user.UserName);
                    command.Parameters.AddWithValue("@PasswordHash", user.PasswordHash);
                    command.Parameters.AddWithValue("@PasswordSalt", user.PasswordSalt);
                    command.Parameters.AddWithValue("@RefreshToken", user.RefreshToken);
                    command.Parameters.AddWithValue("@TokenCreated", user.TokenCreated);
                    command.Parameters.AddWithValue("@TokenExpires", user.TokenExpires);

                    await command.ExecuteNonQueryAsync();
                }
            }
        }

        public static async Task InsertRefreshTokenAsync(RefreshToken refreshToken, int userId)
        {
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                await connection.OpenAsync();

                using (SqlCommand command = new SqlCommand("InsertRefreshToken", connection))
                {
                    command.CommandType = CommandType.StoredProcedure;
                    command.Parameters.AddWithValue("@Token", refreshToken.Token);
                    command.Parameters.AddWithValue("@UserId", userId);
                    command.Parameters.AddWithValue("@Created", refreshToken.Created);
                    command.Parameters.AddWithValue("@Expires", refreshToken.Expires);

                    await command.ExecuteNonQueryAsync();
                }
            }
        }
    }

}
