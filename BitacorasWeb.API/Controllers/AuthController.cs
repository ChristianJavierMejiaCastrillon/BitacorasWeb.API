using BitacorasWeb.API.Datos;
using System;
using System.Data;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Web.Http;

namespace BitacorasWeb.API.Controllers
{
    public class AuthController : ApiController
    {
        [HttpPost]
        [Route("api/auth/login")]
        public IHttpActionResult Login(LoginRequest request)
        {
            if (request == null ||
                string.IsNullOrEmpty(request.Usuario) ||
                string.IsNullOrEmpty(request.Password))
            {
                return Ok(new
                {
                    success = false,
                    message = "Datos incompletos"
                });
            }

            const string sql = @"
                SELECT PasswordHash, PasswordSalt
                FROM Usuario
                WHERE UsuarioLogin = @Usuario
                AND Activo = 1";

            using (SqlConnection con = ConexionBD.CrearConexion())
            using (SqlCommand cmd = new SqlCommand(sql, con))
            {
                cmd.Parameters.Add("@Usuario", SqlDbType.NVarChar, 50).Value = request.Usuario;

                con.Open();

                using (SqlDataReader dr = cmd.ExecuteReader())
                {
                    if (!dr.Read())
                    {
                        return Ok(new
                        {
                            success = false,
                            message = "Usuario o contraseña incorrectos"
                        });
                    }

                    if (dr["PasswordHash"] == DBNull.Value ||
                        dr["PasswordSalt"] == DBNull.Value)
                    {
                        return Ok(new
                        {
                            success = false,
                            message = "Usuario sin contraseña configurada"
                        });
                    }

                    byte[] hashDb = (byte[])dr["PasswordHash"];
                    byte[] saltDb = (byte[])dr["PasswordSalt"];

                    if (!VerifyPassword(request.Password, saltDb, hashDb))
                    {
                        return Ok(new
                        {
                            success = false,
                            message = "Usuario o contraseña incorrectos"
                        });
                    }

                    return Ok(new
                    {
                        success = true,
                        message = "Autenticación satisfactoria"
                    });
                }
            }
        }
        private static byte[] HashPassword(string password, byte[] salt)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(32);
            }
        }
        private static bool VerifyPassword(string password, byte[] salt, byte[] expectedHash)
        {
            byte[] computed = HashPassword(password, salt);

            if (computed.Length != expectedHash.Length)
                return false;

            int diff = 0;

            for (int i = 0; i < computed.Length; i++)
                diff |= computed[i] ^ expectedHash[i];

            return diff == 0;
        }
    }
    public class LoginRequest
    {
        public string Usuario { get; set; }
        public string Password { get; set; }
    }
}