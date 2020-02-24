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
--  hidden_args.keyhex
--              (string) The ebox key (as a hex encoded string). Not present
--                       when staging an ebox.

args = ...

oldbox = nil
key = nil

if args.hidden_args and args.hidden_args.keyhex then
    key = args.hidden_args.keyhex
end

-- Nonexistent _user_ properties don't return an error, instead they
-- just return nil for their value
oldbox, source = zfs.get_prop(args.dataset, args.prop)

-- If the property is inherited, treat it like it's not set
if (source ~= args.dataset) then
    oldbox = nil
end

zfs.debug("Adding ebox as " .. args.prop ..
    " to " .. args.dataset ..
    ": " ..  args.ebox)

-- Try to make sure everything will work before we try it
err = zfs.check.set_prop(args.dataset, args.prop, args.ebox)
if err ~= 0 then
    zfs.debug(err)
    return err
end

if key then
    err = zfs.check.change_key(args.dataset, key, 'hex')
    if err ~= 0 then
        return err
    end
end

-- The sync commands shouldn't fail if the checks passed, but out of
-- an abundance of caution, try to undo if they do end up failing for
-- some reason.
err = zfs.sync.set_prop(args.dataset, args.prop, args.ebox)
if err ~= 0 and oldbox then
    zfs.sync.set_prop(args.dataset, args.prop, oldbox)
    return err
end

if key then
    err = zfs.sync.change_key(args.dataset, key, 'hex')
    if err ~= 0 and oldbox then
        zfs.sync.set_prop(args.dataset, args.prop, oldbox)
    end
end
