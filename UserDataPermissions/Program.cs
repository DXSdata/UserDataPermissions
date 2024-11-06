using System;
using System.IO;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;

namespace UserDataPermissions;

class Program
{
    static void Main(string[] args)
    {
        //Permissions according to https://technet.microsoft.com/en-us/library/jj649078(v=ws.11).aspx with change of Administratos having full access
        //Child directories must be equal to the user names!

        //optional: start from a custom userdir folder. useful for debugging
        var startFromReached = Settings.Default.startFrom == "";
        var settingsFile = "UserDataPermissions.exe.config";
        
        if (!File.Exists(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\" + settingsFile))
        {
            Log(settingsFile + " does not exist in exe dir -> exiting.");
            Environment.ExitCode = -30;
            return;
        }

        var settings = Settings.Default;

        //Parent (UserData)
        Log(settings.pathUserData + ": Setting parent permissions");
        var parent = new DirectoryInfo(settings.pathUserData);

        if (!parent.Exists)
        {
            Log("Dir does not exist -> exiting.");
            Environment.ExitCode = -10;
            return;
        }

        if (settings.domain == "")
        {
            Log("Please set your domain name in config file -> exiting.");
            Environment.ExitCode = -40;
            return;
        }

        DirectorySecurity sec;

        if (!settings.skipParentPermissions)
        {
            sec = new DirectorySecurity(parent.FullName, AccessControlSections.All);
            sec.SetAccessRuleProtection(true, false); //ignore inherited
            RemoveExplicitSecurity(sec);
            try
            {
                foreach (var user in Settings.Default.fullAccessUsers)
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

        foreach(var userdir in parent.GetDirectories())
        {
            Log(userdir.FullName);

            if (settings.exceptions.Contains(userdir.Name))
            {
                Log("Skipping " + userdir.FullName);
                continue;
            }

            if (userdir.Name == settings.startFrom)
                startFromReached = true;

            if (!startFromReached)
            {
                Log("Skipping " + userdir.Name + " (looking for " + settings.startFrom + " to start from)");
                continue;
            }

            IdentityReference user = new NTAccount(settings.domain, userdir.Name);
           
            try
            {
                user.Translate(typeof(SecurityIdentifier)); //only necessary to check if user exists in domain
            }
            catch (IdentityNotMappedException)
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
            foreach (var usersubdir in userdir.GetDirectories("*.*", SearchOption.AllDirectories))
            {
                if (settings.debug)
                    Log("    " + usersubdir.FullName);

                TryCatch(() =>
                {
                    sec = new DirectorySecurity(usersubdir.FullName, AccessControlSections.All);
                    RemoveExplicitSecurity(sec);
                    sec.SetAccessRuleProtection(false, false);
                    //sec.AddAccessRule(new FileSystemAccessRule(usersubdir.Name, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                    sec.SetOwner(user);
                    usersubdir.SetAccessControl(sec);
                }, usersubdir.FullName);               
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

                TryCatch(() => {
                    filesec = new FileSecurity(userfile.FullName, AccessControlSections.All);
                    RemoveExplicitSecurity(filesec);
                    filesec.SetAccessRuleProtection(false, false);
                    //sec.AddAccessRule(new FileSystemAccessRule(userfile.Name, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                    filesec.SetOwner(user);
                    userfile.SetAccessControl(filesec);
                }, userfile.FullName);                
            }
        }
        Log("Done");
    }

    static void RemoveExplicitSecurity(DirectorySecurity directorySecurity)
    {
        var rules = directorySecurity.GetAccessRules(true, false, typeof(NTAccount));
        foreach (FileSystemAccessRule rule in rules)
            directorySecurity.RemoveAccessRule(rule);
    }

    static void RemoveExplicitSecurity(FileSecurity fileSecurity)
    {
        var rules = fileSecurity.GetAccessRules(true, false, typeof(NTAccount));
        foreach (FileSystemAccessRule rule in rules)
            fileSecurity.RemoveAccessRule(rule);
    }

    static void Log(string text) => Console.WriteLine(text);

    static void TryCatch(Action a, string dataFriendly)
    {
        try
        {
            a();
        }
        catch (ArgumentOutOfRangeException e)
        {
            Log($"{e.Message}: {dataFriendly}");
        }
        catch (ArgumentException)
        {
            Log("Error processing file (path might be too long): " + dataFriendly);
        }
        catch (IdentityNotMappedException e)
        {
            Log($"{e.Message}{Environment.NewLine}{e.StackTrace}: {dataFriendly}");
        }
    }
    
}
