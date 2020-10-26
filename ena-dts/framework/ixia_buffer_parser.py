# BSD LICENSE
#
# Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
Helper class that parses a list of files containing IXIA captured frames
extracting a sequential number on them.

The captured files look like this. They all contain a two lines header which
needs to be removed.


    Frames 1 to 10 of 20
    Frame,Time Stamp,DA,SA,Type/Length,Data,Frame Length,Status
    1    1203:07:01.397859720    00 00 00 00 00 00    00 00 00 00 00 00    00 01    00 00 00 00 ...
    2    1203:07:01.397860040    00 00 00 00 00 00    00 00 00 00 00 00    00 01    00 00 00 01 ...
    3    ...

Every line after the header shows the information of a single frame. The class
will extract the sequential number at the beginning of the packet payload.

              time-stamp                                                             sequence
         V                  V                                                       V         V
    2    1203:07:01.397860040    00 00 00 00 00 00    00 00 00 00 00 00    00 01    00 00 00 01 ...


Check the unit tests for more information about how the class works.
"""


class IXIABufferFileParser(object):

    def __init__(self, filenames):
        self.frames_files = []
        self.counter = 0
        self.__read_files(filenames)
        self._next_file()

    def __read_files(self, filenames):
        """
        Reads files from a list of file names and store the file objects in a
        internal list to be used later on. It leaves the files ready to be
        processed by reading and discarding the first two lines on each file.
        """
        for filename in filenames:
            a_file = open(filename, 'r')
            self.__discard_headers(a_file)
            self.frames_files.append(a_file)

    def __discard_headers(self, frame_file):
        """
        Discards the first two lines (header) leaving only the frames
        information ready to be read.
        """
        if frame_file.tell() == 0:
            frame_file.readline()
            frame_file.readline()

    def __get_frame_number(self, frame):
        """
        Given a line from the file, it extracts the sequential number by
        knowing exactly where it should be.
        The counter is part of the frame's payload which is the 3rd element
        starting from the back if we split the line by \t.
        The counter only takes chars inside the payload.
        """
        counter = frame.rsplit('\t', 3)[1]
        counter = counter[:11]
        return int(counter.replace(' ', ''), 16)

    def __change_current_file(self):
        """
        Points the current open file to the next available from the internal
        list. Before making the change, it closes the 'old' current file since
        it won't be used anymore.
        """
        if self.counter > 0:
            self.current_file.close()
        self.current_file = self.frames_files[self.counter]
        self.counter += 1

    def _next_file(self):
        """
        Makes the current file point to the next available file if any.
        Otherwise the current file will be None.
        """
        if self.counter < len(self.frames_files):
            self.__change_current_file()
            return True
        else:
            self.current_file = None
            return False

    def read_all_frames(self):
        """
        Goes through all the open files on its internal list, reads one
        line at the time and returns the sequential number on that frame.
        When one file is completed (EOF) it will automatically switch to the
        next one (if any) and continue reading.

        This function allows calls like:

            for frame in frame_parser.read_all_frames():
                do_something(frame)
        """
        while True:
            frameinfo = self.current_file.readline().strip()
            if not frameinfo:
                if not self._next_file():
                    break
                continue
            yield self.__get_frame_number(frameinfo)
