-- This file and its contents are supplied under the terms of the
-- Common Development and Distribution License ("CDDL"), version 1.0.
-- You may only use this file in accordance with the terms of version
-- 1.0 of the CDDL.
--
-- A full copy of the text of the CDDL should have accompanied this
-- source.  A copy of the CDDL is also available via the Internet at
-- http://www.illumos.org/license/CDDL.

-- Copyright 2019 Joyent, Inc.

-- This adds an ebox to a dataset as a zfs property, and sets the dataset
-- key as well. This is used both to stage a new ebox and to unilaterally
-- set a new ebox, bypassing the staging set.

-- args should contain the following keys:
--  dataset     (string) The dataset we're updating
--  prop        (string) The property we're setting
--  ebox        (string) The ebox (as a base64 string)
--  keyhex      (string) The ebox key (as a hex encoded string). Not present
--                       when staging an ebox.

args = ...

oldbox = nil
key = nil

if args.keyhex then
    -- Due to limitations to the current zcp API, we cannot pass a raw binary
    -- value as an argument. Instead, we pass the key as a hex string and
    -- so we can convert it within the channel program
    key = args.keyhex:gsub('..', function (ch)
        return string.char(tonumber(ch, 16))
    end
end

for prop, source in zfs.list.properties(args.dataset) do
    if prop == args.prop then
        oldbox = zfs.get_prop(args.dataset, args.prop)
    end
end

-- Try to make sure everything will work before we try it
err = zfs.check.set_prop(args.dataset, args.prop, args.ebox)
if err then
    return err
end

if key then
    err = zfs.check.change_key(args.dataset, key)
    if err then
        return err
    end
end

-- The sync commands shouldn't fail if the checks passed, but out of
-- an abundance of caution, try to undo if they do end up failing for
-- some reason.
err = zfs.sync.set_prop(args.dataset, args.prop, args.ebox)
if err and oldbox then
    zfs.sync.set_prop(args.dataset, args.prop, oldbox)
    return err
end

if args.keyhex then
    err = zfs.sync.change_key(args.dataset, key)
    if err and oldbox then
        zfs.sync.set_prop(args.dataset, args.prop, oldbox)
    end
end
