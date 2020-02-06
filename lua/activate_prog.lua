-- This file and its contents are supplied under the terms of the
-- Common Development and Distribution License ("CDDL"), version 1.0.
-- You may only use this file in accordance with the terms of version
-- 1.0 of the CDDL.
--
-- A full copy of the text of the CDDL should have accompanied this
-- source.  A copy of the CDDL is also available via the Internet at
-- http://www.illumos.org/license/CDDL.

-- Copyright 2020 Joyent, Inc.

-- This will replace the current ebox with the staged ebox value, and
-- update the dataset wrapping key

-- args should contain the following keys:
--  dataset     (string)    The dataset to act on
--  ebox        (string)    The zfs property of the current ebox
--  stagedebox  (string)    The zfs property of the staged ebox
--  keyhex      (string)    The staged ebox key (as a hex encoded string).

args = ...

-- Due to limitations to the current zcp API, we cannot pass a raw binary
-- value as an argument. Instead, we pass the key as a hex string and
-- so we can convert it within the channel program
key = args.keyhex:gsub('..',
    function (ch)
        return string.char(tonumber(ch, 16))
    end
)

hasold = false
hasnew = false
oldebox = nil

-- zfs.get_prop returns nil for non-existent _user_ properties, but
-- also treat an inherited property as not set

oldebox, source = zfs.get_prop(args.dataset, args.ebox)
if (oldebox ~= nil and source == args.dataset) then
    hasold = true
    zfs.debug("Old ebox is '" .. oldebox .. "'")
end

newebox, source = zfs.get_prop(args.dataset, args.stagedebox)
if (newebox ~= nil and source == args.dataset) then
    hasnew = true
end

if (not hasnew) then
    return "No ebox has been staged"
end

err = zfs.check.change_key(args.dataset, key)
if err ~= 0 then
    return err
end

err = zfs.check.set_prop(args.dataset, args.ebox, newebox)
if err ~= 0 then
    return err
end

err = zfs.check.inherit(args.dataset, args.stagedebox)
if err ~= 0 then
    return err
end

err = zfs.sync.set_prop(args.dataset, args.ebox, newebox)
if err ~= 0 then
    return err
end

err = zfs.sync.change_key(args.dataset, key)
if err ~= 0 and hasold then
    zfs.sync.set_prop(args.dataset, args.ebox, oldebox)
    return err
end

-- This this fails (it really shouldn't since we did the check first,
-- but just in case), there's not much to do here -- it means both
-- the staged and active ebox properties will have the same value and
-- an operator would just need to manually delete the staged one after
-- fixing the failure.
err = zfs.sync.inherit(args.dataset, args.stagedebox)
if err ~= 0 then
    return err
end
