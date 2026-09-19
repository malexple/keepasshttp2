using System;
using KeePassLib;
using KeePassLib.Keys;
using KeePassLib.Serialization;

namespace KeePassLibTestNet8
{
    class Program
    {
        static void Main(string[] args)
        {
            string dbPath = @"D:\project\zig\keepasshttp2\testbd.kdbx";
            string masterPassword = "123456";

            var ioc = IOConnectionInfo.FromPath(dbPath);

            var key = new CompositeKey();
            key.AddUserKey(new KcpPassword(masterPassword));

            var db = new PwDatabase();
            db.Open(ioc, key, null);

            Console.WriteLine($"Database opened. IsOpen={db.IsOpen}, Name={db.Name}");

            var entries = db.RootGroup.GetEntries(true);
            Console.WriteLine($"Entry count: {entries.UCount}");

            foreach (var entry in entries)
            {
                string title = entry.Strings.ReadSafe(PwDefs.TitleField);
                string url = entry.Strings.ReadSafe(PwDefs.UrlField);
                string user = entry.Strings.ReadSafe(PwDefs.UserNameField);
                string pass = entry.Strings.ReadSafe(PwDefs.PasswordField);

                Console.WriteLine($"Title='{title}' Url='{url}' User='{user}' Password='{pass}' UUID={entry.Uuid.ToHexString()}");
            }

            db.Close();
        }
    }
}
