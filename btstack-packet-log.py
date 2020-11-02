#
# convert log output to PacketLogger format and open in PacketLogger(mac) or Wireshark
#

import sublime
import sublime_plugin


import re
import sys
import time
import os
import tempfile
import subprocess

default_date="2001-01-01"
default_hours = 12 
packet_counter = 0
last_time = default_date + " " + str(default_hours) + ":00:00.000"

def chop(line, prefix):
	if line.startswith(prefix):
		return line[len(prefix):]
	return None

def str2hex(value):
	if value:
		return int(value, 16)
	return None

def arrayForNet32(value):
	return bytearray([value >> 24, (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff])

def generateTimestamp(t):
	global last_time
	global packet_counter

	# use last_time if time missing for this entry
	if not t:
		t = last_time
	if t:
		last_time = t

		# check for date
		parts = t.split(' ')
		have_date = True
		if len(parts) == 1:
			# only time, prepend fixed date
			have_date = False
			t = "2000-01-01 " + t;

		# handle ms
		try: 
			(t1, t2) = t.split('.')
			if t1 and t2:
				t_obj   = time.strptime(t1, "%Y-%m-%d %H:%M:%S")
				tv_sec  = int(time.mktime(t_obj)) 
				if not have_date:
					# start at 12:00
					tv_sec += 12*60*60
				tv_usec = int(t2) * 1000
				return (tv_sec, tv_usec)
		except ValueError:
			# print 'Cannot parse time', t
			pass

	packet_counter += 1
	return (packet_counter, 0)

def dumpPacket(fout, timestamp, type, data):
	length = 9 + len(data)
	(tv_sec, tv_usec) = generateTimestamp(timestamp)
	fout.write(arrayForNet32(length))
	fout.write(arrayForNet32(tv_sec))
	fout.write(arrayForNet32(tv_usec))
	fout.write(bytearray([type]))
	fout.write(data)

def handleHexPacket(fout, timestamp, type, text):
	try:
		data = bytearray(list(map(str2hex, text.strip().split())))
		dumpPacket(fout, timestamp, type, data)
	except TypeError:
		print('Cannot parse hexdump', text.strip())

def processText(text, fout):
	packet_counter = 0
	line_conter = 0
	for line in text.splitlines():
		try:
			line_conter += 1
			timestamp = None
			# strip newlines
			line = line.strip("\n\r")
			# skip empty lines
			if len(line) == 0: 
				continue
			parts = re.match('\[(.*)\] (.*)', line)
			if parts and len(parts.groups()) == 2:
				(timestamp, line) = parts.groups()
			rest = chop(line,'CMD => ')
			if rest:
				handleHexPacket(fout, timestamp, 0, rest)
				continue
			rest = chop(line,'EVT <= ')
			if rest:
				handleHexPacket(fout, timestamp, 1, rest)
				continue
			rest = chop(line,'ACL => ')
			if rest:
				handleHexPacket(fout, timestamp, 2, rest)
				continue
			rest = chop(line,'ACL <= ')
			if rest:
				handleHexPacket(fout, timestamp, 3, rest)
				continue
			rest = chop(line,'SCO => ')
			if rest:
				handleHexPacket(fout, timestamp, 8, rest)
				continue
			rest = chop(line,'SCO <= ')
			if rest:
				handleHexPacket(fout, timestamp, 9, rest)
				continue
			rest = chop(line,'LOG -- ')
			if rest:
				line = rest
			dumpPacket(fout, timestamp, 0xfc, line.encode('ascii'))
		except:
			print("Error in line %u: '%s'" % (line_conter, line))



class BtstackPacketLogCommand(sublime_plugin.TextCommand):
	def run(self, edit):
		# get window content
		content = self.view.substr(sublime.Region(0, self.view.size()))
		# create temp file
		outfile = tempfile.NamedTemporaryFile(mode='w+b', suffix='.pklg')
		# create pklg from window content
		processText(content, outfile)
		# try to open pklg in PacketLogger (mac) or Wireshark (other)
		if sublime.platform() == "osx":
			subprocess.call(["open", outfile.name])
		else:
			subprocess.call(["wireshark", outfile.name])
