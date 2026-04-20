using System.Configuration;
using System.Data.SqlClient;

namespace BitacorasWeb.API.Datos
{
    public class ConexionBD
    {
        public static SqlConnection CrearConexion()
        {
            string cadena = ConfigurationManager
                .ConnectionStrings["TQ_Bitacoras"]
                .ConnectionString;

            return new SqlConnection(cadena);
        }
    }
}