#include <glib.h>
#include <glib/gprintf.h>

#include "ns-wine-library.h"

ns_RESULT
ns_GetLibraryInfo (ns_LIBRARYINFO *LibraryInfo, uint32 LibraryInfoSize)
{

  //FIXME assert size equalness

  g_snprintf (LibraryInfo->szCreator, 64, "ICNF G-Node <http://www.gnode.org>");
  g_snprintf (LibraryInfo->szDescription, 64, "Neuroshare Wine Proxy Library");
  
  LibraryInfo->dwAPIVersionMaj = 1;
  LibraryInfo->dwAPIVersionMin = 3;
  
  LibraryInfo->dwLibVersionMaj = 0;
  LibraryInfo->dwLibVersionMin = 1;

  LibraryInfo->dwTime_Year = 2011;
  LibraryInfo->dwTime_Month = 1;
  LibraryInfo->dwTime_Day = 1;
  LibraryInfo->dwFlags = 0;
  LibraryInfo->dwMaxFiles = 256;
  LibraryInfo->dwFileDescCount = 0;

  return ns_OK;
}

ns_RESULT
ns_OpenFile (char *filename, uint32 *file_handle)
{
  
  
  return ns_OK;
}

