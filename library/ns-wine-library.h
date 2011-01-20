/*
 * Copyright © 2011 Christian Kellner <kellner@bio.lmu.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the licence, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: Christian Kellner <kellner@bio.lmu.de>
 */


#ifndef _NS_WINE_LIBRARY_H_
#define _NS_WINE_LIBRARY_H_

#include <nsAPItypes.h>
#include <nsWireProtocol.h>


ns_RESULT ns_GetLibraryInfo       (ns_LIBRARYINFO   *LibraryInfo,
				   uint32            LibraryInfoSize);
ns_RESULT ns_OpenFile             (char             *filename,
				   uint32           *file_id);
ns_RESULT ns_CloseFile            (uint32            file_id);
ns_RESULT ns_GetFileInfo          (uint32            file_id,
				   ns_FILEINFO      *FileInfo,
				   uint32            FileInfoSize);
ns_RESULT ns_GetEntityInfo        (uint32            file_id,
				   uint32            EntityID,
				   ns_ENTITYINFO    *EntityInfo,
				   uint32            EntityInfoSize);
ns_RESULT ns_GetEventInfo         (uint32            file_id,
				   uint32            EntityID,
				   ns_EVENTINFO     *EventInfo,
				   uint32            EventInfoSize);
ns_RESULT ns_GetEventData         (uint32            file,
				   uint32            EntityID,
				   uint32            Index,
				   double           *TimeStamp,
				   void             *Data,
				   uint32            DataSize,
				   uint32           *DataRetSize);
ns_RESULT ns_GetAnalogInfo        (uint32            file_id,
				   uint32            EntityID,
				   ns_ANALOGINFO    *AnalogInfo,
				   uint32            AnalogInfoSize);
ns_RESULT ns_GetAnalogData        (uint32            file_id,
				   uint32            EntityID,
				   uint32            StartIndex,
				   uint32            IndexCount,
				   uint32           *ContCount,
				   double           *Data);
ns_RESULT ns_GetSegmentInfo       (uint32            file_id,
				   uint32            EntityID,
				   ns_SEGMENTINFO   *SegmentInfo,
				   uint32            SegmentInfoSize);
ns_RESULT ns_GetSegmentSourceInfo (uint32            file_id,
				   uint32            EntityID,
				   uint32            SourceID,
				   ns_SEGSOURCEINFO *SourceInfo,
				   uint32            SourceInfoSize);
ns_RESULT ns_GetSegmentData       (uint32            file_id,
				   uint32            EntityID,
				   uint32            Index,
				   double           *TimeStamp,
				   double           *Data,
				   uint32            DataBufferSize,
				   uint32           *SampleCount,
				   uint32           *UnitID);
ns_RESULT ns_GetNeuralInfo        (uint32            file_id,
				   uint32            EntityID,
				   ns_NEURALINFO    *NeuralInfo,
				   uint32            NeuralInfoSize);
ns_RESULT ns_GetNeuralData        (uint32            file_id,
				   uint32            EntityID,
				   uint32            StartIndex,
				   uint32            IndexCount,
				   double           *Data);
ns_RESULT ns_GetIndexByTime       (uint32            file_id,
				   uint32            EntityID,
				   double            Time,
				   int32             Flags,
				   uint32           *Index);
ns_RESULT ns_GetTimeByIndex       (uint32            file_id,
				   uint32            EntityID,
				   uint32            Index,
				   double           *Time);
ns_RESULT ns_GetLastErrorMsg      (char             *MsgBuffer,
				   uint32            MsgBufferSize);




#endif


