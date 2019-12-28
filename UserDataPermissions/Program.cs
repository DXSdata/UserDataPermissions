using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace UserDataPermissions
{
    class Program
    {
        static void Main(string[] args)
        {
            //Permissions according to https://technet.microsoft.com/en-us/library/jj649078(v=ws.11).aspx with change of Administratos having full access
            //Child directories must be equal to the user names!

            //optional: start from a custom userdir folder. useful for debugging
            bool startFromReached = Settings.Default.startFrom == "";
            String settingsFile = "UserDataPermissions.exe.config";

            if (!File.Exists(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + "\\" + settingsFile))
            {
                Log(settingsFile + " does not exist in exe dir -> exiting.");
                Environment.ExitCode = -30;
                return;
            }

            //Parent (UserData)
            Log(Settings.Default.pathUserData + ": Setting parent permissions");
            DirectoryInfo parent = new DirectoryInfo(Settings.Default.pathUserData);

            if (!parent.Exists)
            {
                Log("Dir does not exist -> exiting.");
                Environment.ExitCode = -10;
                return;
            }

            if (Settings.Default.domain == "")
            {
                Log("Please set your domain name in config file -> exiting.");
                Environment.ExitCode = -40;
                return;
            }

            DirectorySecurity sec;

            if (!Settings.Default.skipParentPermissions)
            {
                sec = new DirectorySecurity(parent.FullName, AccessControlSections.All);
                sec.SetAccessRuleProtection(true, false); //ignore inherited
                RemoveExplicitSecurity(sec);
                try
                {
                    foreach (String user in Settings.Default.fullAccessUsers)
                        sec.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                    sec.AddAccessRule(new FileSystemAccessRule(Settings.Default.defaultGroup, FileSystemRights.ListDirectory | FileSystemRights.CreateDirectories | FileSystemRights.ReadAttributes | FileSystemRights.ReadExtendedAttributes | FileSystemRights.ReadPermissions, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
                    sec.AddAccessRule(new FileSystemAccessRule(Settings.Default.ownersGroup, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly, AccessControlType.Allow));
                    parent.SetAccessControl(sec);
                }
                catch (IdentityNotMappedException ex)
                {
                    Log("Did not find users or groups in your system -> exiting. Maybe your OS uses a different language, please adjust user or group names.\r\nMessage details: " + ex.Message);
                    Environment.ExitCode = -20;
                    return;
                }
            }
            else
                Log("Skipping parent permissions.");


            Log("Giving executing user restore privileges");
            UnmanagedCode.GiveRestorePrivilege(); //otherwise invalidoperationexception at setowner()

            foreach(DirectoryInfo userdir in parent.GetDirectories())
            {
                Log(userdir.FullName);

                if (Settings.Default.exceptions.Contains(userdir.Name))
                {
                    Log("Skipping " + userdir.FullName);
                    continue;
                }

                if (userdir.Name == Settings.Default.startFrom)
                    startFromReached = true;

                if (!startFromReached)
                {
                    Log("Skipping " + userdir.Name + " (looking for " + Settings.Default.startFrom + " to start from)");
                    continue;
                }

                IdentityReference user = new NTAccount(Settings.Default.domain, userdir.Name);
               
                try
                {
                    user.Translate(typeof(SecurityIdentifier)); //only necessary to check if user exists in domain
                }
                catch(IdentityNotMappedException)
                {
                    Log(" User " + userdir.Name + " not found in domain " + Settings.Default.domain);
                    continue;
                }

                sec = new DirectorySecurity(userdir.FullName, AccessControlSections.All);
                RemoveExplicitSecurity(sec);
                sec.SetAccessRuleProtection(false, false); //inherit
                //optional: Set file access right explicitly; not necessary because of creator-owner permission set in parent
                //sec.AddAccessRule(new FileSystemAccessRule(userdir.Name, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                sec.SetOwner(user);
                userdir.SetAccessControl(sec);

                //Subdirs
                Log("  Processing subdirs");
                foreach (DirectoryInfo usersubdir in userdir.GetDirectories("*.*", SearchOption.AllDirectories))
                {
                    if (Settings.Default.debug)
                        Log("    " + usersubdir.FullName);

                    sec = new DirectorySecurity(usersubdir.FullName, AccessControlSections.All);
                    RemoveExplicitSecurity(sec);
                    sec.SetAccessRuleProtection(false, false);
                    //sec.AddAccessRule(new FileSystemAccessRule(usersubdir.Name, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                    sec.SetOwner(user);
                    usersubdir.SetAccessControl(sec);
                }

                //Subfiles
                Log("  Processing subfiles");
                foreach(FileInfo userfile in userdir.GetFiles("*.*", SearchOption.AllDirectories))
                {
                    if (!userfile.Exists) //prevent FileNotFoundException if application runs for a longer time
                        continue;

                    if (Settings.Default.debug)
                        Log("    " + userfile.FullName);

                    FileSecurity filesec;

                    try
                    {
                        filesec = new FileSecurity(userfile.FullName, AccessControlSections.All);
                        RemoveExplicitSecurity(filesec);
                        filesec.SetAccessRuleProtection(false, false);
                        //sec.AddAccessRule(new FileSystemAccessRule(userfile.Name, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                        filesec.SetOwner(user);
                        userfile.SetAccessControl(filesec);
                    }
                    catch (ArgumentException)
                    {
                        Log("Error processing file (path might be too long): " + userfile.FullName);
                        continue;
                    }

                }

            }
            Log("Done");

        }

        private static void RemoveExplicitSecurity(DirectorySecurity directorySecurity)
        {
            AuthorizationRuleCollection rules = directorySecurity.GetAccessRules(true, false, typeof(System.Security.Principal.NTAccount));
            foreach (FileSystemAccessRule rule in rules)
                directorySecurity.RemoveAccessRule(rule);
        }

        private static void RemoveExplicitSecurity(FileSecurity fileSecurity)
        {
            AuthorizationRuleCollection rules = fileSecurity.GetAccessRules(true, false, typeof(System.Security.Principal.NTAccount));
            foreach (FileSystemAccessRule rule in rules)
                fileSecurity.RemoveAccessRule(rule);
        }

        private static void Log(String text)
        {
            Console.WriteLine(text);
        }
    }
}
