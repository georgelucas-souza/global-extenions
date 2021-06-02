using Newtonsoft.Json;
using System;
using System.Globalization;
using System.Text;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Reflection;
using System.Data;
using System.Dynamic;
using System.Linq;
using System.ComponentModel.DataAnnotations.Schema;
using Oracle.ManagedDataAccess.Client;
using System.Data.SqlClient;

namespace GlobalExtensions
{
    public static class Gx
    {
        public static class DataBase
        {
            public static List<object> ReadSqlServer(string connection, string query)
            {
                DataTable dt = new DataTable();

                using (var conn = new SqlConnection(connection))
                {
                    conn.Open();
                    using (var cmd = new SqlCommand(query, conn))
                    {
                        using (var da = new SqlDataAdapter(cmd))
                        {
                            da.Fill(dt);
                        }
                    }
                }

                return dt.ToGenericObjectList();
            }

            public static List<T> ReadSqlServer<T>(string connection, string query)
            {
                var objList = ReadSqlServer(connection, query);

                return objList.ToObjectList<T>();
            }

            public static List<object> ReadOracle(string connection, string query)
            {
                DataTable dt = new DataTable();

                using (var conn = new OracleConnection(connection))
                {
                    conn.Open();
                    using (var cmd = new OracleCommand(query, conn))
                    {
                        using (var da = new OracleDataAdapter(cmd))
                        {
                            da.Fill(dt);
                        }
                    }
                }

                return dt.ToGenericObjectList();
            }

            public static List<T> ReadOracle<T>(string connection, string query)
            {
                var objList = ReadOracle(connection, query);

                return objList.ToObjectList<T>();
            }
        }
        public static string TrimDefault(this string text, string defaultText = "0")
        {
            return string.IsNullOrEmpty(text.Trim()) ? defaultText : text.Trim();
        }

        public static string RemoveDiacritics(this string text)
        {
            var normalizedString = text.Normalize(NormalizationForm.FormD);
            var stringBuilder = new StringBuilder();

            foreach (var c in normalizedString)
            {
                var unicodeCategory = CharUnicodeInfo.GetUnicodeCategory(c);
                if (unicodeCategory != UnicodeCategory.NonSpacingMark)
                {
                    stringBuilder.Append(c);
                }
            }

            return stringBuilder.ToString().Normalize(NormalizationForm.FormC);
        }

        public static string ToJson<T>(this T obj)
        {
            return JsonConvert.SerializeObject(obj, Formatting.Indented);
        }
        
        public static string Normalize(this string txt, string[] lookingFor, string changeTo = "")
        {
            if (lookingFor.Contains(txt))
            {
                return changeTo;
            }
            else
            {
                return txt;
            }
        }

        public static T DeepClone<T>(this T obj)
        {
            var json = obj.ToJson();
            return JsonConvert.DeserializeObject<T>(json);
        }

        public static DateTime ToDateTime(this string text, string format = "yyyy-MM-dd HH:mm:ss", string formatLanguage = "en-US", DateTime? defaultDate = null)
        {
            DateTime defaulValue = defaultDate ?? new DateTime(1970, 1, 1, 0, 0, 0);

            format = string.IsNullOrEmpty(format) ? "yyyy-MM-dd HH:mm:ss" : format;
            CultureInfo ci = string.IsNullOrEmpty(formatLanguage.Trim()) ? CultureInfo.InvariantCulture : CultureInfo.CreateSpecificCulture(formatLanguage);

            DateTime.TryParseExact(text, format, ci, DateTimeStyles.None, out defaulValue);

            return defaulValue;
        }

        public static int WeekNumber(this DateTime date, string formatLanguage = "en-US")
        {
            var currentCulture = CultureInfo.CreateSpecificCulture(formatLanguage);

            int weekNo = currentCulture.Calendar.GetWeekOfYear(
                            date,
                            CalendarWeekRule.FirstFullWeek,
                            DayOfWeek.Sunday);

            return weekNo;
        }


        public static int DayOfWeekNumber(this DateTime date)
        {
            return (int)date.Date.DayOfWeek;
        }

        public static string DayOfWeekName(this DateTime date, bool addOrder)
        {
            if (addOrder)
            {
                return date.DayOfWeekNumber().ToString() + "-" + date.Date.DayOfWeek.ToString();
            }
            else
            {
                return date.Date.DayOfWeek.ToString();
            }
        }

        public static string EncryptText(this string text, string password, string salt = null)
        {
            byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(text);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt ?? "########");


            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesEncrypted = AESEncrypt(bytesToBeEncrypted, passwordBytes, saltBytes);

            string result = Convert.ToBase64String(bytesEncrypted);

            return result;
        }

        public static string DecryptText(this string text, string password, string salt = null)
        {
            try
            {
                byte[] bytesToBeDecrypted = Convert.FromBase64String(text);
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] saltBytes = Encoding.UTF8.GetBytes(salt ?? "########");

                passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

                byte[] bytesDecrypted = AESDecrypt(bytesToBeDecrypted, passwordBytes, saltBytes);

                string result = Encoding.UTF8.GetString(bytesDecrypted);

                return result;
            }
            catch
            {
                return text;
            }
        }

        private static byte[] AESEncrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes, byte[] saltByteArray)
        {
            byte[] encryptedBytes = null;

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltByteArray, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }

        private static byte[] AESDecrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes, byte[] saltByteArray)
        {
            byte[] decryptedBytes = null;


            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltByteArray, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }

        public static Bitmap ToBitmap(this byte[] bytes)
        {
            var bmp = new Bitmap(new System.IO.MemoryStream(bytes));

            return bmp;
        }

        public static byte[] ToBytes(this Bitmap img)
        {
            using (var stream = new MemoryStream())
            {
                img.Save(stream, System.Drawing.Imaging.ImageFormat.Png);
                return stream.ToArray();
            }
        }

        public static PropertyInfo GetProperty<T>(this T obj, string property)
        {
            return obj.GetType().GetProperty(property);
        }

        public static object GetPropertyValue<T>(this T obj, string property)
        {
            return obj.GetProperty(property).GetValue(obj);
        }

        public static PropertyInfo[] GetProperties<T>(this T obj)
        {
            return obj.GetType().GetProperties();
        }

        public static void SetProperty<T>(this T obj, string property, object value)
        {
            var propertyValue = obj.GetProperty(property);
            if (propertyValue != null)
            {
                propertyValue.SetValue(obj, value);
            }
        }

        public static List<PropertyVariance> CompareWith<T>(this T referenceObject, T targetObject)
        {
            List<PropertyVariance> variances = new List<PropertyVariance>();

            PropertyInfo[] properties = referenceObject.GetProperties();
            foreach (PropertyInfo property in properties)
            {
                var reference = referenceObject.GetPropertyValue(property.Name) ?? string.Empty;
                var diference = targetObject.GetPropertyValue(property.Name) ?? string.Empty;

                if (!reference.Equals(diference))
                {
                    variances.Add(new PropertyVariance()
                    {
                        Property = property.Name,
                        Value = diference
                    });
                }
            }

            return variances;
        }

        public static void SetPropertiesTo<T>(this List<PropertyVariance> variances, T obj)
        {
            foreach (var variance in variances)
            {
                var objProperty = obj.GetProperty(variance.Property);
                if (objProperty != null)
                {
                    objProperty.SetValue(obj, variance.Value);
                }
            }
        }

        public static void SetProperties<T>(this T obj, List<PropertyVariance> variances)
        {
            foreach (var variance in variances)
            {
                var objProperty = obj.GetProperty(variance.Property);
                if (objProperty != null)
                {
                    obj.SetProperty(variance.Property, variance.Value);
                }
            }
        }

        public static List<object> ToGenericObjectList(this DataTable dt)
        {
            List<object> objList = new List<object>();

            if (dt.Rows.Count > 0)
            {
                var columns = dt.Columns;

                for (int i = 0; i < dt.Rows.Count; i++)
                {
                    ExpandoObject newLineObj = new ExpandoObject();

                    foreach (DataColumn column in columns)
                    {
                        object cellValue = dt.Rows[i][column.ColumnName];

                        if (cellValue.GetType() == typeof(DBNull))
                        {
                            if (cellValue.GetType() == typeof(string))
                            {
                                ((IDictionary<string, object>)newLineObj)[column.ColumnName] = string.Empty;
                            }
                            else
                            {
                                ((IDictionary<string, object>)newLineObj)[column.ColumnName] = null;
                            }
                        }
                        else
                        {
                            ((IDictionary<string, object>)newLineObj)[column.ColumnName] = Convert.ChangeType(cellValue, column.DataType);
                        }
                    }

                    objList.Add(newLineObj);

                }
            }

            return objList;
        }

        public static T ToObject<T>(this object genericObj)
        {
            Type newObjType = typeof(T);
            T newObject = (T)Activator.CreateInstance(newObjType);

            PropertyInfo[] objectProperties = newObject.GetProperties();

            foreach (var property in objectProperties)
            {
                var objectAttributes = property.GetCustomAttributes(false);
                var columnDefine = objectAttributes.Where(w => w.GetType() == typeof(ColumnAttribute)).FirstOrDefault();
                if (columnDefine != null)
                {
                    var attributeName = ((ColumnAttribute)columnDefine).Name;
                    var propertyValue = ((IDictionary<string, object>)genericObj)[attributeName];

                    if (property.PropertyType.IsGenericType && property.PropertyType.GetGenericTypeDefinition().Equals(typeof(Nullable<>)))
                    {
                        var nulableType = Nullable.GetUnderlyingType(property.PropertyType);
                        var convertPropertyValueToType = Convert.ChangeType(propertyValue, nulableType);
                        property.SetValue(newObject, convertPropertyValueToType);
                    }
                    else
                    {
                        var convertPropertyValueToType = Convert.ChangeType(propertyValue, property.PropertyType);
                        property.SetValue(newObject, convertPropertyValueToType);
                    }

                }
            }

            return newObject;
        }

        public static List<T> ToObjectList<T>(this List<object> genericObjList)
        {
            List<T> objectList = new List<T>();

            foreach(var item in genericObjList)
            {
                objectList.Add(item.ToObject<T>());
            }

            return objectList;
        }



    }
}
