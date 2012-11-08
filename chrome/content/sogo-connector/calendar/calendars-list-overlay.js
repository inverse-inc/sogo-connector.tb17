let iCc = Components.classes;
let iCi = Components.interfaces;

function reinitCalendarCache(aCalendar) {
    let superCalendar = aCalendar.superCalendar.wrappedJSObject;
    if (superCalendar && superCalendar.mCachedCalendar) {
        let storageCalendar = superCalendar.mCachedCalendar.wrappedJSObject;
        let listener = {
            onDeleteCalendar: function reinitCalendarCache_onDeleteCalendar(cal, code, empty) {
                dump("Storage emptied. Restarting...\n");
                let appStartup = iCc["@mozilla.org/toolkit/app-startup;1"].getService(iCi.nsIAppStartup);
                appStartup.quit(iCi.nsIAppStartup.eRestart | iCi.nsIAppStartup.eForceQuit);
            }
        };

        dump("Deleting storage data...\n");
        storageCalendar.deleteCalendar(storageCalendar, listener);
    }
}
