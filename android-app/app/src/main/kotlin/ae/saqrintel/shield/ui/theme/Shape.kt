package ae.saqrintel.shield.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Immutable
import androidx.compose.ui.unit.dp

/** Saqr radii: cards 16, controls 12, pills full. */
@Immutable
data class SaqrShapes(
    /** Cards on the canvas and sheets. Never nest a card in a card. */
    val card: RoundedCornerShape = RoundedCornerShape(16.dp),
    /** Buttons, fields, wells inside a card. */
    val control: RoundedCornerShape = RoundedCornerShape(12.dp),
    val pill: RoundedCornerShape = RoundedCornerShape(percent = 50),
)
