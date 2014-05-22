#!/usr/bin/python
# -*- coding:utf-8 -*-

msgs = []

def append(msg):
	msgs.append(msg)

def all():
	return(msgs)

def last(num=0):
	if num == 0:
		return(msgs)
	elif num >= len(msgs):
		return(msgs)
	else:
		return(msgs[len(msgs)-num:])
