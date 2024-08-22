using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Data.SQLite;
using Microsoft.Data.Sqlite;


public class WindowSniffer
{
    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

    static void Main(string[] args)
    {
        string dbFilePath = @"window_log.db";



        using (var connection = new SqliteConnection($"Data Source={dbFilePath};Version=3;"))
        {
            connection.Open();

            string createTableQuery = @"
                CREATE TABLE IF NOT EXISTS WindowLog (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    WindowTitle TEXT NOT NULL,
                    OpenTime TEXT NOT NULL,
                    DurationSeconds REAL NOT NULL
                )";

            using (var command = new SQLiteCommand(createTableQuery, connection))
            {
                command.ExecuteNonQuery();
            }
        }

        string currentWindow = null;
        DateTime lastChange = DateTime.Now;

        using (var connection = new SQLiteConnection($"Data Source={dbFilePath};Version=3;"))
        {
            connection.Open();

            while (true)
            {
                StringBuilder windowTitle = new StringBuilder(256);
                IntPtr handle = GetForegroundWindow();
                GetWindowText(handle, windowTitle, windowTitle.Capacity);

                string newWindow = windowTitle.ToString();
                DateTime now = DateTime.Now;

                if (currentWindow != newWindow)
                {
                    if (currentWindow != null)
                    {
                        // window  change
                        TimeSpan duration = now - lastChange;

                        //time spent at the window
                        string insertQuery = "INSERT INTO WindowLog (WindowTitle, OpenTime, DurationSeconds) VALUES (@title, @openTime, @duration)";
                        using (var command = new SQLiteCommand(insertQuery, connection))
                        {
                            command.Parameters.AddWithValue("@title", currentWindow);
                            command.Parameters.AddWithValue("@openTime", lastChange.ToString("o")); command.Parameters.AddWithValue("@duration", duration.TotalSeconds);
                            command.ExecuteNonQuery();
                        }
                    }

                    // new  window  
                    currentWindow = newWindow;
                    lastChange = now;
                }

                Console.Clear();
                Console.WriteLine($"Current Window: {currentWindow}");

                Thread.Sleep(1000);
            }
        }
    }
}
