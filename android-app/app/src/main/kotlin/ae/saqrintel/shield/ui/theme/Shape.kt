package ae.saqrintel.shield.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Immutable
import androidx.compose.ui.unit.dp

/** Night Grid radii: stamp 6, control 12, inset 16, tile 20, pill full. */
@Immutable
data class SaqrShapes(
    val stamp: RoundedCornerShape = RoundedCornerShape(6.dp),
    val control: RoundedCornerShape = RoundedCornerShape(12.dp),
    val inset: RoundedCornerShape = RoundedCornerShape(16.dp),
    /** Top-level tiles on the canvas. Never nest a tile in a tile. */
    val tile: RoundedCornerShape = RoundedCornerShape(20.dp),
    val pill: RoundedCornerShape = RoundedCornerShape(percent = 50),
)
