//! Functions for doing Network Interactions.

const std = @import("std");
const fs = std.fs;
const fmt = std.fmt;
const log = std.log;
const mem = std.mem;
const meta = std.meta;
const net = std.net;
const os = std.os;
const process = std.process;
const time = std.time;

const lib = @import("zinglib.zig");
const consts = lib.constants;
const Addresses = lib.Addresses;
const Datagrams = lib.Datagrams;

