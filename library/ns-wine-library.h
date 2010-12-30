
#ifndef _NS_WINE_LIBRARY_H_
#define _NS_WINE_LIBRARY_H_

#include <neuroshare.h>


ns_RESULT ns_GetLibraryInfo (ns_LIBRARYINFO *LibraryInfo, uint32 LibraryInfoSize);
ns_RESULT ns_OpenFile (char *filename, uint32 *file_handle);

#endif
