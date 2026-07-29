use anyhow::Result;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use std::io::Cursor;

use crate::capture::Packet;

/// Serialize *packets* into an indented XML string.
///
/// Output shape:
/// ```xml
/// <?xml version="1.0" encoding="UTF-8"?>
/// <packets>
///   <packet number="1">
///     <layer name="eth">
///       <field name="eth.dst" value="ffffffffffff" display="Broadcast"/>
///       ...
///     </layer>
///     <layer name="ip">
///       <field name="ip.src" value="c0a80101" display="192.168.1.1"/>
///       ...
///     </layer>
///   </packet>
/// </packets>
/// ```
pub fn packets_to_xml(packets: &[Packet]) -> Result<String> {
    let mut w = Writer::new_with_indent(Cursor::new(Vec::new()), b' ', 2);

    // <?xml version="1.0" encoding="UTF-8"?>
    w.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;

    // <packets>
    w.write_event(Event::Start(BytesStart::new("packets")))?;

    for pkt in packets {
        // <packet number="N">
        let mut pkt_tag = BytesStart::new("packet");
        pkt_tag.push_attribute(("number", pkt.number.to_string().as_str()));
        w.write_event(Event::Start(pkt_tag))?;

        for layer in &pkt.layers {
            // <layer name="...">
            let mut layer_tag = BytesStart::new("layer");
            layer_tag.push_attribute(("name", layer.name.as_str()));
            w.write_event(Event::Start(layer_tag))?;

            for field in &layer.fields {
                // <field name="..." value="..." display="..."/>
                let mut f = BytesStart::new("field");
                f.push_attribute(("name", field.name.as_str()));
                f.push_attribute(("value", field.value.as_str()));
                f.push_attribute(("display", field.display.as_str()));
                w.write_event(Event::Empty(f))?;
            }

            w.write_event(Event::End(BytesEnd::new("layer")))?;
        }

        w.write_event(Event::End(BytesEnd::new("packet")))?;
    }

    w.write_event(Event::End(BytesEnd::new("packets")))?;

    Ok(String::from_utf8(w.into_inner().into_inner())?)
}
