// Copyright (c) 2016, Stephen Gallagher <sgallagh@redhat.com>
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from this
//    software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

func (sc *SscgConfig) writeTemporaryFile(dest string, data []byte) (string, error) {
	DebugLogger.Printf("Opening temporary file")
	tempFile, err := ioutil.TempFile(sc.cwd, "sscg-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening temporary file: %v\n", err)
		return "", err
	}
	defer func() {
		if cerr := tempFile.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "Could not close tempfile: %v\n", cerr)
			if err == nil {
				// We were fine until this happened, so return this as the
				// error. Otherwise, we don't want to clobber the real reason
				// we are failing.
				err = cerr
			}
		}
	}()

	tempFilename := tempFile.Name()
	DebugLogger.Printf("Temporary file created at %s\n", tempFilename)

	_, err = tempFile.Write(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing to temporary file: %v\n", err)
		return tempFilename, err
	}
	DebugLogger.Printf("File contents written to %s", tempFilename)

	err = tempFile.Sync()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error flushing temporary file: %v\n", err)
		return tempFilename, err
	}

	return tempFilename, nil
}

// WriteSecureFile Write the contents of data to a temporary file, then
// atomically move it to the destination.
func (sc *SscgConfig) WriteSecureFile(dest string, data []byte) error {
	// Dump the data to a randomly-named file on the disk
	destDir := filepath.Dir(dest)
	tempFilename, err := sc.writeTemporaryFile(destDir, data)
	if err != nil {
		if len(tempFilename) > 0 {
			// Clean up the temporary file if it is laying around
			rerr := os.Remove(tempFilename)
			if rerr != nil {
				fmt.Fprintf(os.Stderr, "Could not delete temporary file %s: %v\n", tempFilename, rerr)
			}
		}
		return err
	}

	// Move the file into its final location
	err = os.Rename(tempFilename, dest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)

		// Clean up the temporary file if it is laying around
		rerr := os.Remove(tempFilename)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "Could not delete temporary file %s: %v\n", tempFilename, rerr)
		}

		return err
	}
	DebugLogger.Printf("Moved %s to %s\n", tempFilename, dest)

	return nil
}

func (sc *SscgConfig) AppendToFile(dest string, data []byte) error {
	outputFile, err := os.OpenFile(dest, os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not open %s for appending.", dest)
		return err
	}
	defer func() {
		if cerr := outputFile.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "Could not close %s: %v\n", dest, cerr)
			if err == nil {
				// We were fine until this happened, so return this as the
				// error. Otherwise, we don't want to clobber the real reason
				// we are failing.
				err = cerr
			}
		}
	}()

	DebugLogger.Printf("%s opened for appending.", dest)

	_, err = outputFile.Write(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing to %s: %v\n", dest, err)
		return err
	}
	DebugLogger.Printf("File contents appended to %s", dest)

	return nil
}

func (sc *SscgConfig) SamePath(src string, dest string) (bool, error) {
	DebugLogger.Printf("Comparing %s to %s\n", src, dest)

	// First, get the absolute paths
	absoluteSrcPath, err := filepath.Abs(src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting absolute path for %s", src)
		return false, err
	}
	DebugLogger.Printf("Absolute src path: %s\n", absoluteSrcPath)

	absoluteDestPath, err := filepath.Abs(dest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting absolute path for %s", dest)
		return false, err
	}
	DebugLogger.Printf("Absolute dest path: %s\n", absoluteDestPath)

	// Next, evaluate any symlinks
	deSymlinkedSrcPath, err := filepath.EvalSymlinks(absoluteSrcPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error evaluating symlinks for %s", absoluteSrcPath)
		return false, err
	}
	DebugLogger.Printf("Absolute src path following symlinks: %s\n", deSymlinkedSrcPath)

	deSymlinkedDestPath, err := filepath.EvalSymlinks(absoluteDestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error evaluating symlinks for %s", absoluteDestPath)
		return false, err
	}
	DebugLogger.Printf("Absolute dest path following symlinks: %s\n", deSymlinkedDestPath)

	// Finally, clean up any cruft
	cleanedSrcPath := filepath.Clean(deSymlinkedSrcPath)
	DebugLogger.Printf("Cleaned src path: %s\n", cleanedSrcPath)

	cleanedDestPath := filepath.Clean(deSymlinkedDestPath)
	DebugLogger.Printf("Cleaned dest path: %s\n", cleanedDestPath)

	matched := cleanedSrcPath == cleanedDestPath
	DebugLogger.Printf("Paths match: %t\n", matched)

	return matched, nil
}
